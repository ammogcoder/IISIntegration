// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Server.IISIntegration
{
    internal class IISHttpServer : IServer
    {
        private static NativeMethods.PFN_REQUEST_HANDLER _requestHandler = HandleRequest;
        private static NativeMethods.PFN_SHUTDOWN_HANDLER _shutdownHandler = HandleShutdown;
        private static NativeMethods.PFN_ASYNC_COMPLETION _onAsyncCompletion = OnAsyncCompletion;
        private static NativeMethods.PFN_CLIENT_DISCONNECT_HANDLER _clientDisconnectHandler = HandleClientDisconnect; 

        private IISContextFactory _iisContextFactory;
        private readonly MemoryPool _memoryPool = new MemoryPool();
        private GCHandle _httpServerHandle;
        private readonly IApplicationLifetime _applicationLifetime;
        private readonly IAuthenticationSchemeProvider _authentication;
        private readonly IISOptions _options;
        
        public IFeatureCollection Features { get; } = new FeatureCollection();

        public IISHttpServer(IApplicationLifetime applicationLifetime, IAuthenticationSchemeProvider authentication, IOptions<IISOptions> options)
        {
            _applicationLifetime = applicationLifetime;
            _authentication = authentication;
            _options = options.Value;

            if (_options.ForwardWindowsAuthentication)
            {
                authentication.AddScheme(new AuthenticationScheme(IISDefaults.AuthenticationScheme, _options.AuthenticationDisplayName, typeof(IISServerAuthenticationHandler)));
            }
        }

        public Task StartAsync<TContext>(IHttpApplication<TContext> application, CancellationToken cancellationToken)
        {
            _httpServerHandle = GCHandle.Alloc(this);

            _iisContextFactory = new IISContextFactory<TContext>(_memoryPool, application, _options);

            // Start the server by registering the callback
            NativeMethods.register_callbacks(_requestHandler, _shutdownHandler, _onAsyncCompletion, _clientDisconnectHandler, (IntPtr)_httpServerHandle, (IntPtr)_httpServerHandle);

            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            // TODO: Drain pending requests

            // Stop all further calls back into managed code by unhooking the callback

            return Task.CompletedTask;
        }

        public void Dispose()
        {
            if (_httpServerHandle.IsAllocated)
            {
                _httpServerHandle.Free();
            }

            _memoryPool.Dispose();
        }

        private static NativeMethods.REQUEST_NOTIFICATION_STATUS HandleRequest(IntPtr pInProcessHandler, IntPtr pvRequestContext)
        {
            // Unwrap the server so we can create an http context and process the request
            var server = (IISHttpServer)GCHandle.FromIntPtr(pvRequestContext).Target;

            var context = server._iisContextFactory.CreateHttpContext(pInProcessHandler);

            var task = Task.Run(() => context.ProcessRequestAsync());

            task.ContinueWith((t, state) => CompleteRequest(t, (IISHttpContext)state), context);

            return NativeMethods.REQUEST_NOTIFICATION_STATUS.RQ_NOTIFICATION_PENDING;
        }

        private static bool HandleShutdown(IntPtr pvRequestContext)
        {
            var server = (IISHttpServer)GCHandle.FromIntPtr(pvRequestContext).Target;
            server._applicationLifetime.StopApplication();
            return true;
        }

        private static NativeMethods.REQUEST_NOTIFICATION_STATUS OnAsyncCompletion(IntPtr pvManagedHttpContext, int hr, int bytes)
        {
            var context = (IISHttpContext)GCHandle.FromIntPtr(pvManagedHttpContext).Target;
            context.OnAsyncCompletion(hr, bytes);
            return NativeMethods.REQUEST_NOTIFICATION_STATUS.RQ_NOTIFICATION_PENDING;
        }

        private static bool HandleClientDisconnect(IntPtr pInProcessHandler, IntPtr pvManagedHttpContext)
        {
            var context = (IISHttpContext)GCHandle.FromIntPtr(pvManagedHttpContext).Target;
            context.Abort(null);
            return true;
        }

        private static void CompleteRequest(Task<bool> completedTask, IISHttpContext context)
        {
            // Post completion after completing the request to resume the state machine
            context.PostCompletion(ConvertRequestCompletionResults(completedTask.Result));
            // Dispose the context
            context.Dispose();
        }

        private static NativeMethods.REQUEST_NOTIFICATION_STATUS ConvertRequestCompletionResults(bool success)
        {
            return success ? NativeMethods.REQUEST_NOTIFICATION_STATUS.RQ_NOTIFICATION_CONTINUE
                                                     : NativeMethods.REQUEST_NOTIFICATION_STATUS.RQ_NOTIFICATION_FINISH_REQUEST;
        }

        private class IISContextFactory<T> : IISContextFactory
        {
            private readonly IHttpApplication<T> _application;
            private readonly MemoryPool _memoryPool;
            private readonly IISOptions _options;

            public IISContextFactory(MemoryPool memoryPool, IHttpApplication<T> application, IISOptions options)
            {
                _application = application;
                _memoryPool = memoryPool;
                _options = options;
            }

            public IISHttpContext CreateHttpContext(IntPtr pInProcessHandler)
            {
                return new IISHttpContextOfT<T>(_memoryPool, _application, pInProcessHandler, _options);
            }
        }
    }

    // Over engineering to avoid allocations...
    internal interface IISContextFactory
    {
        IISHttpContext CreateHttpContext(IntPtr pInProcessHandler);
    }
}
