// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.HttpSys.Internal;
using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Server.IISIntegration
{
    internal partial class IISHttpContext
    {
        /// <summary>
        /// Reads data from the Input pipe to the user.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            // Start a task which will continuously call ReadFromIISAsync and WriteToIISAsync
            StartProcessingRequestAndResponseBody();

            while (true)
            {
                var result = await Input.Reader.ReadAsync();
                var readableBuffer = result.Buffer;
                try
                {
                    if (!readableBuffer.IsEmpty)
                    {
                        var actual = Math.Min(readableBuffer.Length, count);
                        readableBuffer = readableBuffer.Slice(0, actual);
                        readableBuffer.CopyTo(buffer);
                        return (int)actual;
                    }
                    else if (result.IsCompleted)
                    {
                        return 0;
                    }
                }
                finally
                {
                    Input.Reader.AdvanceTo(readableBuffer.End, readableBuffer.End);
                }
            }
        }

        /// <summary>
        /// Writes data to the output pipe.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public Task WriteAsync(ArraySegment<byte> data, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (!HasResponseStarted)
            {
                return WriteAsyncAwaited(data, cancellationToken);
            }

            lock (_stateSync)
            {
                DisableReads();
                return Output.WriteAsync(data, cancellationToken: cancellationToken);
            }
        }

        /// <summary>
        /// Flushes the data in the output pipe
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task FlushAsync(CancellationToken cancellationToken = default(CancellationToken))
        {
            // Issue: On first flush for websockets, we need to flush the headers such that
            // IIS will know that an upgrade occured.
            // If we don't have anything on the Output pipe, the TryRead in ReadAndWriteLoopAsync
            // will fail and we will signal the upgradeTcs that we are upgrading. However, we still
            // didn't flush.
            // There are a few ways to fix it:
            // 1. Swap the order to Output.FlushAsync and InitializeResponse (which will start the read/write loop)
            // 2. Call FlushAsync() inside IHttpUpgradeFeature.UpgradeAsync(). This unfortunately will cause
            //    ReadAsync to read 0 bytes before upgrading.
            await Output.FlushAsync(cancellationToken);
            await InitializeResponse(0);
        }

        public void StartProcessingRequestAndResponseBody()
        {
            if (_processBodiesTask == null)
            {
                lock (_createReadWriteBodySync)
                {
                    if (_processBodiesTask == null)
                    {
                        _processBodiesTask = ConsumeAsync();
                    }
                }
            }
        }

        private async Task WriteAsyncAwaited(ArraySegment<byte> data, CancellationToken cancellationToken)
        {
            // WriteAsyncAwaited is only called for the first write to the body.
            // Ensure headers are flushed if Write(Chunked)Async isn't called.
            await InitializeResponseAwaited(data.Count);

            Task writeTask;
            lock (_stateSync)
            {
                DisableReads();

                // Want to guarantee that data has been written to the pipe before releasing the lock.
                writeTask = Output.WriteAsync(data, cancellationToken: cancellationToken);
            }
            await writeTask;
        }

        // ConsumeAsync is called when either the first read or first write is done. 
        // There are two modes for reading and writing to the request/response bodies.
        // 1. Await all reads and try to read from the Output pipe
        // 2. Done reading and await all writes.
        private async Task ConsumeAsync()
        {
            await ReadAndWriteLoopAsync();

            // If we are done writing, complete the output pipe and return
            // Input Pipe will be closed when ReadAndWriteLoopAsync returns
            if (_doneWriting)
            {
                Output.Reader.Complete();
                return;
            }

            await WriteLoopAsync();
        }

        private unsafe IISAwaitable ReadFromIISAsync(int length)
        {
            lock (_stateSync)
            {
                // We don't want to read if there is data available in the output pipe
                // Therefore, we mark the current operation as cancelled to allow for the read
                // to be requeued.
                if (Output.Reader.TryRead(out var result) && !result.Buffer.IsEmpty)
                {
                    _operation.Complete(hr: IISServerConstants.HResultCancelIO, cbBytes: 0);
                    Output.Reader.AdvanceTo(result.Buffer.Start);
                }
                else
                {
                    var hr = NativeMethods.http_read_request_bytes(
                           _pInProcessHandler,
                           (byte*)_inputHandle.Pointer,
                           length,
                           out var dwReceivedBytes,
                           out bool fCompletionExpected);
                    // if we complete the read synchronously, there is no need to set the reading flag
                    // as there is no cancelable operation.
                    if (!fCompletionExpected)
                    {
                        _operation.Complete(hr, dwReceivedBytes);
                    }
                    else
                    {
                        _reading = true;
                    }
                }

                return _operation;
            }
        }

        private unsafe IISAwaitable WriteToIISAsync(ReadOnlyBuffer<byte> buffer)
        {
            var fCompletionExpected = false;
            var hr = 0;
            var nChunks = 0;

            if (buffer.IsSingleSegment)
            {
                nChunks = 1;
            }
            else
            {
                foreach (var memory in buffer)
                {
                    nChunks++;
                }
            }

            if (buffer.IsSingleSegment)
            {
                var pDataChunks = stackalloc HttpApiTypes.HTTP_DATA_CHUNK[1];

                fixed (byte* pBuffer = &MemoryMarshal.GetReference(buffer.First.Span))
                {
                    ref var chunk = ref pDataChunks[0];

                    chunk.DataChunkType = HttpApiTypes.HTTP_DATA_CHUNK_TYPE.HttpDataChunkFromMemory;
                    chunk.fromMemory.pBuffer = (IntPtr)pBuffer;
                    chunk.fromMemory.BufferLength = (uint)buffer.Length;
                    hr = NativeMethods.http_write_response_bytes(_pInProcessHandler, pDataChunks, nChunks, out fCompletionExpected);
                }
            }
            else
            {
                // REVIEW: Do we need to guard against this getting too big? It seems unlikely that we'd have more than say 10 chunks in real life
                var pDataChunks = stackalloc HttpApiTypes.HTTP_DATA_CHUNK[nChunks];
                var currentChunk = 0;

                // REVIEW: We don't really need this list since the memory is already pinned with the default pool,
                // but shouldn't assume the pool implementation right now. Unfortunately, this causes a heap allocation...
                var handles = new MemoryHandle[nChunks];

                foreach (var b in buffer)
                {
                    ref var handle = ref handles[currentChunk];
                    ref var chunk = ref pDataChunks[currentChunk];

                    handle = b.Retain(true);

                    chunk.DataChunkType = HttpApiTypes.HTTP_DATA_CHUNK_TYPE.HttpDataChunkFromMemory;
                    chunk.fromMemory.BufferLength = (uint)b.Length;
                    chunk.fromMemory.pBuffer = (IntPtr)handle.Pointer;

                    currentChunk++;
                }

                hr = NativeMethods.http_write_response_bytes(_pInProcessHandler, pDataChunks, nChunks, out fCompletionExpected);
                // Free the handles
                foreach (var handle in handles)
                {
                    handle.Dispose();
                }
            }

            if (!fCompletionExpected)
            {
                _operation.Complete(hr, 0);
            }
            return _operation;
        }

        private unsafe IISAwaitable FlushToIISAsync()
        {
            // Calls flush 
            var hr = 0;
            hr = NativeMethods.http_flush_response_bytes(_pInProcessHandler, out var fCompletionExpected);
            if (!fCompletionExpected)
            {
                _operation.Complete(hr, 0);
            }

            return _operation;
        }

        public async Task ReadAndWriteLoopAsync()
        {
            try
            {
                while (!_doneReading)
                {
                    // First we check if there is anything to write from the Output pipe
                    // If there is, we call WriteToIISAsync
                    // Check if Output pipe has anything to write to IIS.
                    if (Output.Reader.TryRead(out var readResult))
                    {
                        var buffer = readResult.Buffer;
                        var consumed = buffer.End;

                        try
                        {
                            if (!buffer.IsEmpty)
                            {
                                // Write to IIS buffers
                                // Guaranteed to write the entire buffer to IIS
                                await WriteToIISAsync(buffer);
                            }
                            else if (readResult.IsCompleted)
                            {
                                _doneWriting = true;
                                break;
                            }
                            else
                            {
                                // Flush of zero bytes
                                await FlushToIISAsync();
                            }
                        }
                        finally
                        {
                            // Always Advance the data pointer to the end of the buffer.
                            Output.Reader.AdvanceTo(buffer.End);
                        }
                    }

                    // Check if there was an upgrade. If there is, we will replace the request and response bodies with
                    // two seperate loops. These will still be using the same Input and Output pipes here.
                    if (_upgradeTcs?.TrySetResult(null) == true)
                    {
                        await StartBidirectionalStream();

                        // Input and Output will be closed in StartBidirectionalStream.
                        // We can return at this point.
                        return;
                    }

                    // Now we handle the read. 
                    var memory = Input.Writer.GetMemory();
                    _inputHandle = memory.Retain(true);

                    try
                    {
                        // Lock around invoking ReadFromIISAsync as we don't want to call CancelIo
                        // when calling read
                        var read = await ReadFromIISAsync(memory.Length);

                        // read value of 0 == done reading
                        // read value of -1 == read cancelled, still allowed to read but we
                        // need a write to occur first. 
                        if (read == 0)
                        {
                            _doneReading = true;
                            continue;
                        }
                        else if (read == -1)
                        {
                            continue;
                        }
                        Input.Writer.Advance(read);
                    }
                    finally
                    {
                        // Always commit any changes to the Input pipe
                        Input.Writer.Commit();
                        _inputHandle.Dispose();
                    }

                    // Flush the read data for the Input Pipe writer
                    var flushResult = await Input.Writer.FlushAsync();

                    // If the pipe was closed, we are done reading, 
                    if (flushResult.IsCompleted || flushResult.IsCancelled)
                    {
                        _doneReading = true;
                    }
                }

                // Complete the input writer as we are done reading the request body.
                Input.Writer.Complete();
            }
            catch (Exception ex)
            {
                Input.Writer.Complete(ex);
            }
        }

        private async Task WriteLoopAsync()
        {
            try
            {
                while (true)
                {
                    // Reading is done, so we will await all reads from the output pipe
                    var readResult = await Output.Reader.ReadAsync();

                    // Get data from pipe
                    var buffer = readResult.Buffer;
                    var consumed = buffer.End;

                    try
                    {
                        // If the output pipe is termniated, cancel the request.
                        if (readResult.IsCancelled)
                        {
                            break;
                        }

                        if (!buffer.IsEmpty)
                        {
                            // Write to IIS buffers
                            // Guaranteed to write the entire buffer to IIS
                            await WriteToIISAsync(buffer);
                        }
                        else if (readResult.IsCompleted)
                        {
                            break;
                        }
                        else
                        {
                            // Flush of zero bytes will 
                            await FlushToIISAsync();
                        }
                    }
                    finally
                    {
                        // Always Advance the data pointer to the end of the buffer.
                        Output.Reader.AdvanceTo(buffer.End);
                    }

                    // Check if there was an upgrade. If there is, we will replace the request and response bodies with
                    // two seperate loops
                    if (_upgradeTcs?.TrySetResult(null) == true)
                    {
                        // The Input pipe has already been completed at this point
                        // Create a new Input pipe for websockets
                        Input = new Pipe(new PipeOptions(_memoryPool, readerScheduler: PipeScheduler.ThreadPool, minimumSegmentSize: MinAllocBufferSize));

                        await StartBidirectionalStream();

                        // Input and Output will be closed in StartBidirectionalStream.
                        // We can return at this point.
                        return;
                    }
                }

                // Close the output pipe as we are done reading from it.
                Output.Reader.Complete();
            }
            catch (Exception ex)
            {
                Output.Reader.Complete(ex);
            }
        }

        // Always called from within a lock
        private void DisableReads()
        {
            // To avoid concurrent reading and writing, if we have a pending read,
            // we must cancel it.
            // _reading will always be false if we upgrade to websockets, so we don't need to check wasUpgrade
            // Also, we set _reading to false after cancelling to detect redundant calls
            if (_reading)
            {
                _reading = false;
                NativeMethods.http_cancel_io(_pInProcessHandler);
            }
        }

    }
}
