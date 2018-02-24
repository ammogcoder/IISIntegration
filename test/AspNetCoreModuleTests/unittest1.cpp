#include "stdafx.h"
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace AspNetCoreModuleTests
{		
	TEST_CLASS(UnitTest1)
	{
	public:
		
		TEST_METHOD(TestMethod1)
		{
            DWORD dwArgc = 0;
            BSTR* pBstrArgv = NULL;
            HRESULT hr = HOSTFXR_UTILITY::ParseHostfxrArguments(
                L"exec \"C:\\Program Files\\dotnet\\test.dll\"",
                L"C:\\Program Files\\dotnet\\dotnet.exe",
                L"C:\\test\\",
                NULL,
                &dwArgc,
                &pBstrArgv);

            Assert::AreEqual(pBstrArgv[0], L"C:\\Program Files\\dotnet\\dotnet.exe");
		}
	};
}
