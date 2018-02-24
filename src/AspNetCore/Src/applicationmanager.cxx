// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

#include "precomp.hxx"

APPLICATION_MANAGER* APPLICATION_MANAGER::sm_pApplicationManager = NULL;

HRESULT
APPLICATION_MANAGER::GetApplicationInfo(
    _In_ IHttpServer*          pServer,
    _In_ ASPNETCORE_CONFIG*    pConfig,
    _Out_ APPLICATION_INFO **  ppApplicationInfo
)
{
    HRESULT                hr = S_OK;
    APPLICATION_INFO      *pApplicationInfo = NULL;
    APPLICATION_INFO_KEY   key;
    BOOL                   fExclusiveLock = FALSE;
    BOOL                   fMixedHostingModelError = FALSE;
    BOOL                   fDuplicatedInProcessApp = FALSE;
    PCWSTR                 pszApplicationId = NULL;
    STACK_STRU ( strEventMsg, 256 );

    *ppApplicationInfo = NULL;

    DBG_ASSERT(pServer != NULL);
    DBG_ASSERT(pConfig != NULL);

    pszApplicationId = pConfig->QueryConfigPath()->QueryStr(); 

    hr = key.Initialize(pszApplicationId);
    if (FAILED(hr))
    {
        goto Finished;
    }

    AcquireSRWLockShared(&m_srwLock);
    if (m_fInShutdown)
    {
        ReleaseSRWLockShared(&m_srwLock);
        hr = HRESULT_FROM_WIN32(ERROR_SERVER_SHUTDOWN_IN_PROGRESS);
        goto Finished;
    }
    m_pApplicationInfoHash->FindKey(&key, ppApplicationInfo);
    ReleaseSRWLockShared(&m_srwLock);

    if (*ppApplicationInfo == NULL)
    {
        switch (pConfig->QueryHostingModel())
        {
        case HOSTING_IN_PROCESS:
            if (m_pApplicationInfoHash->Count() > 0)
            {
                // Only one inprocess app is allowed per IIS worker process
                fDuplicatedInProcessApp = TRUE;
                hr = HRESULT_FROM_WIN32(ERROR_APP_INIT_FAILURE);
                goto Finished;
            }
            break;

        case HOSTING_OUT_PROCESS:
            break;

        default:
            hr = E_UNEXPECTED;
            goto Finished;
        }
        pApplicationInfo = new APPLICATION_INFO(pServer);
        if (pApplicationInfo == NULL)
        {
            hr = E_OUTOFMEMORY;
            goto Finished;
        }

        AcquireSRWLockExclusive(&m_srwLock);
        fExclusiveLock = TRUE;
        if (m_fInShutdown)
        {
            // Already in shuting down. No need to create the application
            hr = HRESULT_FROM_WIN32(ERROR_SERVER_SHUTDOWN_IN_PROGRESS);
            goto Finished;
        }
        m_pApplicationInfoHash->FindKey(&key, ppApplicationInfo);

        if (*ppApplicationInfo != NULL)
        {
            // someone else created the application
            delete pApplicationInfo;
            pApplicationInfo = NULL;
            goto Finished;
        }

        // hosting model check. We do not allow mixed scenario for now
        // could be changed in the future
        if (m_hostingModel != HOSTING_UNKNOWN)
        {
            if (m_hostingModel != pConfig->QueryHostingModel())
            {
                // hosting model does not match, error out
                fMixedHostingModelError = TRUE;
                hr = HRESULT_FROM_WIN32(ERROR_APP_INIT_FAILURE);
                goto Finished;
            }
        }

        hr = pApplicationInfo->Initialize(pConfig, m_pFileWatcher);
        if (FAILED(hr))
        {
            goto Finished;
        }

        hr = m_pApplicationInfoHash->InsertRecord( pApplicationInfo );
        if (FAILED(hr))
        {
            goto Finished;
        }

        //
        // first application will decide which hosting model allowed by this process
        //
        if (m_hostingModel == HOSTING_UNKNOWN)
        {
            m_hostingModel = pConfig->QueryHostingModel();
        }

        *ppApplicationInfo = pApplicationInfo;
        ReleaseSRWLockExclusive(&m_srwLock);
        fExclusiveLock = FALSE;

        pApplicationInfo->StartMonitoringAppOffline();
        pApplicationInfo = NULL;
    }

Finished:

    if (fExclusiveLock)
    {
        ReleaseSRWLockExclusive(&m_srwLock);
    }

    if (pApplicationInfo != NULL)
    {
        pApplicationInfo->DereferenceApplicationInfo();
        pApplicationInfo = NULL;
    }

    if (FAILED(hr))
    {
        if (fDuplicatedInProcessApp)
        {
            if (SUCCEEDED(strEventMsg.SafeSnwprintf(
                ASPNETCORE_EVENT_DUPLICATED_INPROCESS_APP_MSG,
                pszApplicationId)))
            {
                UTILITY::LogEvent(g_hEventLog,
                    EVENTLOG_ERROR_TYPE,
                    ASPNETCORE_EVENT_DUPLICATED_INPROCESS_APP,
                    strEventMsg.QueryStr());
            }
        }
        else if (fMixedHostingModelError)
        {
            if (SUCCEEDED(strEventMsg.SafeSnwprintf(
                ASPNETCORE_EVENT_MIXED_HOSTING_MODEL_ERROR_MSG,
                pszApplicationId,
                pConfig->QueryHostingModel())))
            {
                UTILITY::LogEvent(g_hEventLog,
                    EVENTLOG_ERROR_TYPE,
                    ASPNETCORE_EVENT_MIXED_HOSTING_MODEL_ERROR,
                    strEventMsg.QueryStr());
            }
        }
        else
        {
            if (SUCCEEDED(strEventMsg.SafeSnwprintf(
                ASPNETCORE_EVENT_ADD_APPLICATION_ERROR_MSG,
                pszApplicationId,
                hr)))
            {
                UTILITY::LogEvent(g_hEventLog,
                    EVENTLOG_ERROR_TYPE,
                    ASPNETCORE_EVENT_ADD_APPLICATION_ERROR,
                    strEventMsg.QueryStr());
            }
        }
    }

    return hr;
}

BOOL
APPLICATION_MANAGER::FindConfigChangedApplication(
    _In_ APPLICATION_INFO *     pEntry,
    _In_ PVOID                  pvContext)
{
    CONFIG_CHANGE_CONTEXT* pContext = static_cast<CONFIG_CHANGE_CONTEXT*>(pvContext);
    STRU* pstruConfigPath = pEntry->QueryConfig()->QueryConfigPath();
    BOOL fChanged = pstruConfigPath->StartsWith(pContext->pstrPath, true);
    if (fChanged)
    {
        pContext->MultiSz.Append(*pstruConfigPath);
    }
    return fChanged;
}

HRESULT
APPLICATION_MANAGER::RecycleApplication(
    _In_ LPCWSTR pszApplicationId
)
{
    HRESULT          hr = S_OK;
    APPLICATION_INFO_KEY  key;
    DWORD            dwPreviousCounter = 0;
    APPLICATION_INFO_HASH* table = NULL;
    CONFIG_CHANGE_CONTEXT context;

    hr = key.Initialize(pszApplicationId);
    if (FAILED(hr))
    {
        goto Finished;
    }

    table = new APPLICATION_INFO_HASH();

    if(table == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto Finished;
    }

    //
    // few application expected, small bucket size for hash table
    //
    if (FAILED(hr = table->Initialize(17 /*prime*/)))
    {
        goto Finished;
    }

    context.pstrPath = pszApplicationId;

    AcquireSRWLockExclusive(&m_srwLock);
    dwPreviousCounter = m_pApplicationInfoHash->Count();

    // We don't want to hold the lock for long time as it will block all incoming requests
    // Make a shallow copy of existing hashtable as we may nee to remove nodes
    // This also make sure application shutdown will not be called inside the lock
    m_pApplicationInfoHash->Apply(APPLICATION_INFO_HASH::ReferenceCopyToTable, static_cast<PVOID>(table));
    DBG_ASSERT(dwPreviousCounter == table->Count());
    
    // Removed the applications which are impacted by the configurtion change
    m_pApplicationInfoHash->DeleteIf(FindConfigChangedApplication, (PVOID)&context);

    if (dwPreviousCounter != m_pApplicationInfoHash->Count())
    {
        if (m_hostingModel == HOSTING_IN_PROCESS)
        {
            APPLICATION_INFO_HASH* tmp = m_pApplicationInfoHash;
            m_pApplicationInfoHash = table;
            table = tmp;
            // Keep the original applicationinfo hashtable to continue serve request
            // Trigger a worker process recycle and let the process shutdown code path to handle it
            // So that we will drop/reject the incoming requests before WAS spins another worker process
            g_pHttpServer->RecycleProcess(L"AspNetCore Recycle Process on Demand Due to In-process Application Configuration Changed");
        }
    }

    if (m_pApplicationInfoHash->Count() == 0)
    {
        m_hostingModel = HOSTING_UNKNOWN;
    }

    ReleaseSRWLockExclusive(&m_srwLock);

    if(!context.MultiSz.IsEmpty() && (m_hostingModel == HOSTING_OUT_PROCESS || m_hostingModel == HOSTING_UNKNOWN))
    {
        // some out-of-process applications were removed from the hashtable, i.e., need to be recycled
        PCWSTR path = context.MultiSz.First();
        while (path != NULL)
        {
            APPLICATION_INFO* pRecord;

            // Application got recycled. Log an event
            STACK_STRU(strEventMsg, 256);
            if (SUCCEEDED(strEventMsg.SafeSnwprintf(
                ASPNETCORE_EVENT_RECYCLE_CONFIGURATION_MSG,
                path)))
            {
                UTILITY::LogEvent(g_hEventLog,
                    EVENTLOG_INFORMATION_TYPE,
                    ASPNETCORE_EVENT_RECYCLE_CONFIGURATION,
                    strEventMsg.QueryStr());
            }

            hr = key.Initialize(path);
            if (FAILED(hr))
            {
                goto Finished;
            }

            table->FindKey(&key, &pRecord);
            DBG_ASSERT(pRecord != NULL);

            // shutdown will be done in another thread
            ShutDownApplication(pRecord, NULL);
            pRecord->DereferenceApplicationInfo();
            path = context.MultiSz.Next(path);
        }
    }

Finished:
    if (table != NULL)
    {
        table->Clear();
        delete table;
    }

    if (FAILED(hr))
    {
        // Failed to recycle an application. Log an event
        STACK_STRU(strEventMsg, 256);
        if (SUCCEEDED(strEventMsg.SafeSnwprintf(
            ASPNETCORE_EVENT_RECYCLE_FAILURE_CONFIGURATION_MSG,
            hr)))
        {
            UTILITY::LogEvent(g_hEventLog,
                EVENTLOG_ERROR_TYPE,
                ASPNETCORE_EVENT_RECYCLE_APP_FAILURE,
                strEventMsg.QueryStr());
        }
        // Need to recycle the process as we cannot recycle the application
        g_pHttpServer->RecycleProcess(L"AspNetCore Recycle Process on Demand Due Application Recycle Error");
    }

    return hr;
}

VOID
APPLICATION_MANAGER::ShutDown()
{
    if (!m_fInShutdown)
    {
        m_fInShutdown = TRUE;
        // stop filewatcher monitoring thread
        if (m_pFileWatcher != NULL)
        {
            delete  m_pFileWatcher;
            m_pFileWatcher = NULL;
        }

        if (m_pApplicationInfoHash != NULL)
        {
            AcquireSRWLockExclusive(&m_srwLock);

            // clean up the hash table so that the application will be informed on shutdown
            m_pApplicationInfoHash->Apply(ShutDownApplication, NULL);

            ReleaseSRWLockExclusive(&m_srwLock);
        }
    }
}

//
// Function used by ShutDownApplication thread to do the real shutdown
//
// static
VOID
APPLICATION_MANAGER::DoShutDownApplication(
    LPVOID lpParam)
{
    APPLICATION* pApplication = static_cast<APPLICATION*>(lpParam);
    pApplication->ShutDown();
    pApplication->DereferenceApplication();
}

//
// Function used to shutdown an application
//
// static
VOID
APPLICATION_MANAGER::ShutDownApplication(
    _In_ APPLICATION_INFO *     pEntry,
    _In_ PVOID                  pvContext
)
{
    UNREFERENCED_PARAMETER(pvContext);

    APPLICATION* pApplication = pEntry->QueryApplication();

    // Reference the application first
    pApplication->ReferenceApplication();

    // Reset application pointer to NULL
    // The destructor of ApplictionInfo will not call ShutDown again
    pEntry->ResetApplication();
    HANDLE hThread = CreateThread(
        NULL,       // default security attributes
        0,          // default stack size
        (LPTHREAD_START_ROUTINE)DoShutDownApplication,
        pApplication,       // thread function arguments
        0,          // default creation flags
        NULL);      // receive thread identifier

    CloseHandle(hThread);
}
