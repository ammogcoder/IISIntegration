// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipelines;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpSys.Internal;
using Microsoft.AspNetCore.WebUtilities;

namespace Microsoft.AspNetCore.Server.IISIntegration
{
    internal abstract partial class IISHttpContext : NativeRequestContext, IDisposable
    {
        private const int MinAllocBufferSize = 2048;
        private const int PauseWriterThreshold = 65536;
        private const int ResumeWriterTheshold = 32768;

        private static bool UpgradeAvailable = (Environment.OSVersion.Version >= new Version(6, 2));

        protected readonly IntPtr _pInProcessHandler;

        private bool _reading; // To know whether we are currently in a read operation.
        private bool _doneReading;
        private bool _doneWriting;

        private int _statusCode;
        private string _reasonPhrase;
        private readonly object _onStartingSync = new object();
        private readonly object _onCompletedSync = new object();
        private readonly object _stateSync = new object();
        protected readonly object _createReadWriteBodySync = new object();

        protected Stack<KeyValuePair<Func<object, Task>, object>> _onStarting;
        protected Stack<KeyValuePair<Func<object, Task>, object>> _onCompleted;

        protected Exception _applicationException;
        private readonly MemoryPool _memoryPool;

        private GCHandle _thisHandle;
        private MemoryHandle _inputHandle;
        private IISAwaitable _operation = new IISAwaitable();
        protected Task _readWriteTask;

        protected int _requestAborted;

        private const string NtlmString = "NTLM";
        private const string NegotiateString = "Negotiate";
        private const string BasicString = "Basic";

        internal unsafe IISHttpContext(MemoryPool memoryPool, IntPtr pInProcessHandler, IISOptions options)
            : base((HttpApiTypes.HTTP_REQUEST*)NativeMethods.http_get_raw_request(pInProcessHandler))
        {
            _thisHandle = GCHandle.Alloc(this);

            _memoryPool = memoryPool;
            _pInProcessHandler = pInProcessHandler;

            NativeMethods.http_set_managed_context(pInProcessHandler, (IntPtr)_thisHandle);
            unsafe
            {
                Method = GetVerb();

                RawTarget = GetRawUrl();
                // TODO version is slow.
                HttpVersion = GetVersion();
                Scheme = SslStatus != SslStatus.Insecure ? Constants.HttpsScheme : Constants.HttpScheme;
                KnownMethod = VerbId;

                var originalPath = RequestUriBuilder.DecodeAndUnescapePath(GetRawUrlInBytes());

                if (KnownMethod == HttpApiTypes.HTTP_VERB.HttpVerbOPTIONS && string.Equals(RawTarget, "*", StringComparison.Ordinal))
                {
                    PathBase = string.Empty;
                    Path = string.Empty;
                }
                else
                {
                    // Path and pathbase are unescaped by RequestUriBuilder
                    // The UsePathBase middleware will modify the pathbase and path correctly
                    PathBase = string.Empty;
                    Path = originalPath;
                }

                var cookedUrl = GetCookedUrl();
                QueryString = cookedUrl.GetQueryString() ?? string.Empty;

                // TODO: Avoid using long.ToString, it's pretty slow
                RequestConnectionId = ConnectionId.ToString(CultureInfo.InvariantCulture);

                // Copied from WebListener
                // This is the base GUID used by HTTP.SYS for generating the activity ID.
                // HTTP.SYS overwrites the first 8 bytes of the base GUID with RequestId to generate ETW activity ID.
                // The requestId should be set by the NativeRequestContext
                var guid = new Guid(0xffcb4c93, 0xa57f, 0x453c, 0xb6, 0x3f, 0x84, 0x71, 0xc, 0x79, 0x67, 0xbb);
                *((ulong*)&guid) = RequestId;

                // TODO: Also make this not slow
                TraceIdentifier = guid.ToString();

                var localEndPoint = GetLocalEndPoint();
                LocalIpAddress = localEndPoint.GetIPAddress();
                LocalPort = localEndPoint.GetPort();

                var remoteEndPoint = GetRemoteEndPoint();
                RemoteIpAddress = remoteEndPoint.GetIPAddress();
                RemotePort = remoteEndPoint.GetPort();
                StatusCode = 200;

                RequestHeaders = new RequestHeaders(this);
                HttpResponseHeaders = new HeaderCollection(); // TODO Optimize for known headers
                ResponseHeaders = HttpResponseHeaders;

                if (options.ForwardWindowsAuthentication)
                {
                    WindowsUser = GetWindowsPrincipal();
                    if (options.AutomaticAuthentication)
                    {
                        User = WindowsUser;
                    }
                }

                ResetFeatureCollection();
            }

            RequestBody = new IISHttpRequestBody(this);
            ResponseBody = new IISHttpResponseBody(this);

            Input = new Pipe(new PipeOptions(_memoryPool, readerScheduler: PipeScheduler.ThreadPool, minimumSegmentSize: MinAllocBufferSize));
            var pipe = new Pipe(new PipeOptions(
                _memoryPool,
                readerScheduler: PipeScheduler.ThreadPool,
                pauseWriterThreshold: PauseWriterThreshold,
                resumeWriterThreshold: ResumeWriterTheshold,
                minimumSegmentSize: MinAllocBufferSize));
            Output = new OutputProducer(pipe);
        }

        public Version HttpVersion { get; set; }
        public string Scheme { get; set; }
        public string Method { get; set; }
        public string PathBase { get; set; }
        public string Path { get; set; }
        public string QueryString { get; set; }
        public string RawTarget { get; set; }
        public CancellationToken RequestAborted { get; set; }
        public bool HasResponseStarted { get; set; }
        public IPAddress RemoteIpAddress { get; set; }
        public int RemotePort { get; set; }
        public IPAddress LocalIpAddress { get; set; }
        public int LocalPort { get; set; }
        public string RequestConnectionId { get; set; }
        public string TraceIdentifier { get; set; }
        public ClaimsPrincipal User { get; set; }
        internal WindowsPrincipal WindowsUser { get; set; }
        public Stream RequestBody { get; set; }
        public Stream ResponseBody { get; set; }
        public Pipe Input { get; set; }
        public OutputProducer Output { get; set; }

        public IHeaderDictionary RequestHeaders { get; set; }
        public IHeaderDictionary ResponseHeaders { get; set; }
        private HeaderCollection HttpResponseHeaders { get; set; }
        internal HttpApiTypes.HTTP_VERB KnownMethod { get; }

        public int StatusCode
        {
            get { return _statusCode; }
            set
            {
                if (HasResponseStarted)
                {
                    ThrowResponseAlreadyStartedException(nameof(StatusCode));
                }
                _statusCode = (ushort)value;
            }
        }

        public string ReasonPhrase
        {
            get { return _reasonPhrase; }
            set
            {
                if (HasResponseStarted)
                {
                    ThrowResponseAlreadyStartedException(nameof(ReasonPhrase));
                }
                _reasonPhrase = value;
            }
        }

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

        private async Task WriteAsyncAwaited(ArraySegment<byte> data, CancellationToken cancellationToken)
        {
            await InitializeResponseAwaited(data.Count);

            // WriteAsyncAwaited is only called for the first write to the body.
            // Ensure headers are flushed if Write(Chunked)Async isn't called.

            Task writeTask;
            lock (_stateSync)
            {
                DisableReads();

                // Want to guarantee that data has been written to the pipe before releasing the lock.
                writeTask = Output.WriteAsync(data, cancellationToken: cancellationToken);
            }
            await writeTask;
        }

        /// <summary>
        /// Flushes the data in the output pipe
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task FlushAsync(CancellationToken cancellationToken = default(CancellationToken))
        {
            await InitializeResponse(0);
            await Output.FlushAsync(cancellationToken);
        }

        public void StartProcessingRequestAndResponseBody()
        {
            if (_readWriteTask == null)
            {
                lock (_createReadWriteBodySync)
                {
                    if (_readWriteTask == null)
                    {
                        _readWriteTask = ConsumeAsync();
                    }
                }
            }
        }

        // ConsumeAsync is called when either the first read or first write is done. 
        // There are two modes for reading and writing to the request/response bodies.
        // 1. Await all reads and try to read from the Output pipe
        // 2. Done reading and await all writes.
        public async Task ConsumeAsync()
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

        public async Task ReadAndWriteLoopAsync()
        {
            // First we check if there is anything to write from the Output pipe
            // If there is, we call WriteToIISAsync
            while (!_doneReading)
            {
                // Check if Output pipe has anything to write to IIS.
                if (Output.Reader.TryRead(out var readResult))
                {
                    var buffer = readResult.Buffer;
                    var consumed = buffer.End;

                    try
                    {
                        // If the output pipe is termniated, cancel the request.
                        if (readResult.IsCancelled)
                        {
                            _doneWriting = true;
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
                            // Flush of zero bytes
                            await FlushToIISAsync();
                        }
                    }
                    catch (Exception ex)
                    {
                        throw ex;
                    }
                    finally
                    {
                        // Always Advance the data pointer to the end of the buffer.
                        Output.Reader.AdvanceTo(buffer.End);
                    }
                }

               
                // Check if there was an upgrade. If there is, we will replace the request and response bodies with
                // two seperate loops
                await CheckForUpgrade();

                // Now we handle the read. 
                var wb = Input.Writer.GetMemory();
                _inputHandle = wb.Retain(true);

                try
                {
                    // Lock around invoking ReadFromIISAsync as we don't want to call CancelIo
                    // when calling read
                    var read = await ReadFromIISAsync(wb.Length);

                    // read value of 0 == done reading
                    // read value of -1 == read cancelled, continue trying to read
                    // but don't advance the pipe
                    if (read == 0)
                    {
                        _doneReading = true;
                    }
                    else if (read != -1)
                    {
                        Input.Writer.Advance(read);
                    }
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

                // We are done reading now, set _reading to false.
                // _reading may already be set to false through cancellation, but it is okay to be redundant here.
                lock(_stateSync)
                {
                    _reading = false;
                }
            }

            // Complete the input writer as we are done reading the request body.
            Input.Writer.Complete();
        }

        private async Task WriteLoopAsync()
        {
            // At this point, reading is done, so we will await all reads from the output pipe
            while (true)
            {
                // Always await every write as we are done reading.
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
                await CheckForUpgrade();
            }

            // Close the output pipe as we are done reading from it.
            Output.Reader.Complete();
        }

        private unsafe IISAwaitable FlushToIISAsync()
        {
            // Calls flush 
            lock(_stateSync)
            {
                var hr = 0;
                hr = NativeMethods.http_flush_response_bytes(_pInProcessHandler, out var fCompletionExpected);
                if (!fCompletionExpected)
                {
                    _operation.Complete(hr, 0);
                }
            }
              
            return _operation;
        }

        private void DisableReads()
        {
            // To avoid concurrent reading and writing, if we have a pending read,
            // we must cancel it.
            // _reading will always be false if we upgrade to websockets, so we don't need to check wasUpgrade
            // Also, we set _reading to false after cancelling to detect redundant calls
            if (!_doneReading && _reading)
            {
                _reading = false;
                NativeMethods.http_cancel_io(_pInProcessHandler);
            }
        }

        public Task InitializeResponse(int firstWriteByteCount)
        {
            if (HasResponseStarted)
            {
                return Task.CompletedTask;
            }

            if (_onStarting != null)
            {
                return InitializeResponseAwaited(firstWriteByteCount);
            }

            if (_applicationException != null)
            {
                ThrowResponseAbortedException();
            }

            ProduceStart(appCompleted: false);

            return Task.CompletedTask;
        }

        private async Task InitializeResponseAwaited(int firstWriteByteCount)
        {
            await FireOnStarting();

            if (_applicationException != null)
            {
                ThrowResponseAbortedException();
            }

            ProduceStart(appCompleted: false);
        }

        private void ThrowResponseAbortedException()
        {
            throw new ObjectDisposedException("Unhandled application exception", _applicationException);
        }

        private void ProduceStart(bool appCompleted)
        {
            if (HasResponseStarted)
            {
                return;
            }

            HasResponseStarted = true;

            SendResponseHeaders(appCompleted);

            StartProcessingRequestAndResponseBody();
        }

        protected Task ProduceEnd()
        {
            if (_applicationException != null)
            {
                if (HasResponseStarted)
                {
                    // We can no longer change the response, so we simply close the connection.
                    return Task.CompletedTask;
                }

                // If the request was rejected, the error state has already been set by SetBadRequestState and
                // that should take precedence.
                else
                {
                    // 500 Internal Server Error
                    SetErrorResponseHeaders(statusCode: StatusCodes.Status500InternalServerError);
                }
            }

            if (!HasResponseStarted)
            {
                return ProduceEndAwaited();
            }

            return Task.CompletedTask;
        }

        private void SetErrorResponseHeaders(int statusCode)
        {
            StatusCode = statusCode;
            ReasonPhrase = string.Empty;
            HttpResponseHeaders.Clear();
        }

        private async Task ProduceEndAwaited()
        {
            ProduceStart(appCompleted: true);

            // Force flush
            await Output.FlushAsync();
        }

        public unsafe void SendResponseHeaders(bool appCompleted)
        {
            // Verifies we have sent the statuscode before writing a header
            var reasonPhraseBytes = Encoding.UTF8.GetBytes(ReasonPhrase ?? ReasonPhrases.GetReasonPhrase(StatusCode));

            fixed (byte* pReasonPhrase = reasonPhraseBytes)
            {
                // This copies data into the underlying buffer
                NativeMethods.http_set_response_status_code(_pInProcessHandler, (ushort)StatusCode, pReasonPhrase);
            }

            HttpResponseHeaders.IsReadOnly = true;
            foreach (var headerPair in HttpResponseHeaders)
            {
                var headerValues = headerPair.Value;
                var knownHeaderIndex = HttpApiTypes.HTTP_RESPONSE_HEADER_ID.IndexOfKnownHeader(headerPair.Key);
                if (knownHeaderIndex == -1)
                {
                    var headerNameBytes = Encoding.UTF8.GetBytes(headerPair.Key);
                    for (var i = 0; i < headerValues.Count; i++)
                    {
                        var headerValueBytes = Encoding.UTF8.GetBytes(headerValues[i]);
                        fixed (byte* pHeaderName = headerNameBytes)
                        {
                            fixed (byte* pHeaderValue = headerValueBytes)
                            {
                                NativeMethods.http_response_set_unknown_header(_pInProcessHandler, pHeaderName, pHeaderValue, (ushort)headerValueBytes.Length, fReplace: false);
                            }
                        }
                    }
                }
                else
                {
                    for (var i = 0; i < headerValues.Count; i++)
                    {
                        var headerValueBytes = Encoding.UTF8.GetBytes(headerValues[i]);
                        fixed (byte* pHeaderValue = headerValueBytes)
                        {
                            NativeMethods.http_response_set_known_header(_pInProcessHandler, knownHeaderIndex, pHeaderValue, (ushort)headerValueBytes.Length, fReplace: false);
                        }
                    }
                }
            }
        }

        public void Abort()
        {
            // TODO
        }

        private unsafe IISAwaitable WriteToIISAsync(ReadOnlyBuffer<byte> buffer)
        {
            lock (_stateSync)
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
        }

        private unsafe IISAwaitable ReadFromIISAsync(int length)
        {
            lock (_stateSync)
            {
                // We don't want to read if there is data available in the output pipe
                if (Output.Reader.TryRead(out var result) && !result.Buffer.IsEmpty)
                {
                    _operation.Complete(hr: IISServerConstants.HResultCancelIO, cbBytes: 0);
                    Output.Reader.AdvanceTo(result.Buffer.Start);
                }
                else
                {
                    _reading = true;
                    var hr = NativeMethods.http_read_request_bytes(
                           _pInProcessHandler,
                           (byte*)_inputHandle.Pointer,
                           length,
                           out var dwReceivedBytes,
                           out bool fCompletionExpected);
                    if (!fCompletionExpected)
                    {
                        _operation.Complete(hr, dwReceivedBytes);
                    }
                }

                return _operation;
            }
        }

        public abstract Task<bool> ProcessRequestAsync();

        public void OnStarting(Func<object, Task> callback, object state)
        {
            lock (_onStartingSync)
            {
                if (HasResponseStarted)
                {
                    throw new InvalidOperationException("Response already started");
                }

                if (_onStarting == null)
                {
                    _onStarting = new Stack<KeyValuePair<Func<object, Task>, object>>();
                }
                _onStarting.Push(new KeyValuePair<Func<object, Task>, object>(callback, state));
            }
        }

        public void OnCompleted(Func<object, Task> callback, object state)
        {
            lock (_onCompletedSync)
            {
                if (_onCompleted == null)
                {
                    _onCompleted = new Stack<KeyValuePair<Func<object, Task>, object>>();
                }
                _onCompleted.Push(new KeyValuePair<Func<object, Task>, object>(callback, state));
            }
        }

        protected async Task FireOnStarting()
        {
            Stack<KeyValuePair<Func<object, Task>, object>> onStarting = null;
            lock (_onStartingSync)
            {
                onStarting = _onStarting;
                _onStarting = null;
            }
            if (onStarting != null)
            {
                try
                {
                    foreach (var entry in onStarting)
                    {
                        await entry.Key.Invoke(entry.Value);
                    }
                }
                catch (Exception ex)
                {
                    ReportApplicationError(ex);
                }
            }
        }

        protected async Task FireOnCompleted()
        {
            Stack<KeyValuePair<Func<object, Task>, object>> onCompleted = null;
            lock (_onCompletedSync)
            {
                onCompleted = _onCompleted;
                _onCompleted = null;
            }
            if (onCompleted != null)
            {
                foreach (var entry in onCompleted)
                {
                    try
                    {
                        await entry.Key.Invoke(entry.Value);
                    }
                    catch (Exception ex)
                    {
                        ReportApplicationError(ex);
                    }
                }
            }
        }

        protected void ReportApplicationError(Exception ex)
        {
            if (_applicationException == null)
            {
                _applicationException = ex;
            }
            else if (_applicationException is AggregateException)
            {
                _applicationException = new AggregateException(_applicationException, ex).Flatten();
            }
            else
            {
                _applicationException = new AggregateException(_applicationException, ex);
            }
        }

        public void PostCompletion(NativeMethods.REQUEST_NOTIFICATION_STATUS requestNotificationStatus)
        {
            Debug.Assert(!_operation.HasContinuation, "Pending async operation!");

            var hr = NativeMethods.http_set_completion_status(_pInProcessHandler, requestNotificationStatus);
            if (hr != NativeMethods.S_OK)
            {
                throw Marshal.GetExceptionForHR(hr);
            }

            hr = NativeMethods.http_post_completion(_pInProcessHandler, 0);
            if (hr != NativeMethods.S_OK)
            {
                throw Marshal.GetExceptionForHR(hr);
            }
        }

        public void IndicateCompletion(NativeMethods.REQUEST_NOTIFICATION_STATUS notificationStatus)
        {
            NativeMethods.http_indicate_completion(_pInProcessHandler, notificationStatus);
        }

        internal void OnAsyncCompletion(int hr, int cbBytes)
        {
            // Must acquire the _stateSync here as anytime we call complete, we need to hold the lock
            // to avoid races with cancellation.
            Action continuation;
            lock (_stateSync)
            {
                continuation = _operation.GetCompletion(hr, cbBytes);
            }

            continuation.Invoke();
        }

        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects).
                    _thisHandle.Free();
                }
                if (WindowsUser?.Identity is WindowsIdentity wi)
                {
                    wi.Dispose();
                }
                disposedValue = true;
            }
        }

        // This code added to correctly implement the disposable pattern.
        public override void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }

        private void ThrowResponseAlreadyStartedException(string value)
        {
            throw new InvalidOperationException("Response already started");
        }

        private WindowsPrincipal GetWindowsPrincipal()
        {
            var hr = NativeMethods.http_get_authentication_information(_pInProcessHandler, out var authenticationType, out var token);

            if (hr == 0 && token != IntPtr.Zero && authenticationType != null)
            {
                if ((authenticationType.Equals(NtlmString, StringComparison.OrdinalIgnoreCase)
                    || authenticationType.Equals(NegotiateString, StringComparison.OrdinalIgnoreCase)
                    || authenticationType.Equals(BasicString, StringComparison.OrdinalIgnoreCase)))
                {
                    return new WindowsPrincipal(new WindowsIdentity(token, authenticationType));
                }
            }
            return null;
        }
    }
}
