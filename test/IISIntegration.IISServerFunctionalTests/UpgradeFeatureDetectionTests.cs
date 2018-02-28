// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Server.IntegrationTesting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace Microsoft.AspNetCore.Server.IIS.FunctionalTests
{
    public class UpgradeFeatureDetectionTests : LoggedTest
    {
        public UpgradeFeatureDetectionTests(ITestOutputHelper output) : base(output)
        {
        }

        [Fact]
        public Task UpgradeFeatureDetectionEnabled_IISExpress_CoreClr_x64_Portable()
        {
            return UpgradeFeatureDetectionDeployer(RuntimeFlavor.CoreClr, ApplicationType.Portable, "WebsocketsNotSupported.config", "Disabled");
        }

        [Fact]
        public Task UpgradeFeatureDetectionDisabled_IISExpress_CoreClr_x64_Portable()
        {
            return UpgradeFeatureDetectionDeployer(RuntimeFlavor.CoreClr, ApplicationType.Portable, "WebsocketsSupported.config", "Enabled");
        }

        private async Task UpgradeFeatureDetectionDeployer(RuntimeFlavor runtimeFlavor, ApplicationType applicationType, string configPath, string expected)
        {
            var serverType = ServerType.IISExpress;
            var architecture = RuntimeArchitecture.x64;
            var testName = $"HelloWorld_{runtimeFlavor}";
            using (StartLog(out var loggerFactory, testName))
            {
                var logger = loggerFactory.CreateLogger("HelloWorldTest");

                var deploymentParameters = new DeploymentParameters(Helpers.GetTestSitesPath(), serverType, runtimeFlavor, architecture)
                {
                    EnvironmentName = "UpgradeFeatureDetection", // Will pick the Start class named 'StartupHelloWorld',
                    ServerConfigTemplateContent = (serverType == ServerType.IISExpress) ? File.ReadAllText(configPath) : null,
                    SiteName = "HttpTestSite", // This is configured in the Http.config
                    TargetFramework = "netcoreapp2.0",
                    ApplicationType = applicationType,
                    Configuration =
#if DEBUG
                        "Debug"
#else
                        "Release"
#endif
                };

                using (var deployer = ApplicationDeployerFactory.Create(deploymentParameters, loggerFactory))
                {
                    var deploymentResult = await deployer.DeployAsync();
                    deploymentResult.HttpClient.Timeout = TimeSpan.FromSeconds(5);

                    // Request to base address and check if various parts of the body are rendered & measure the cold startup time.
                    var response = await RetryHelper.RetryRequest(() =>
                    {
                        return deploymentResult.HttpClient.GetAsync("UpgradeFeatureDetection");
                    }, logger, deploymentResult.HostShutdownToken, retryCount: 30);

                    var responseText = await response.Content.ReadAsStringAsync();
                    try
                    {
                        Assert.Equal(expected, responseText);
                    }
                    catch (XunitException)
                    {
                        logger.LogWarning(response.ToString());
                        logger.LogWarning(responseText);
                        throw;
                    }
                }
            }
        }
    }
}
