using FluentAssertions;
using IdentityModel.AspNetCore.AccessTokenManagement;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using IdentityModel.Client;
using Tests.Infrastructure;
using Xunit;

namespace Tests
{
    public class ClientAccessTokenTests
    {

        [Fact]
        public async Task Using_explicit_configuration_with_multiple_client_config_should_succeed()
        {
            var handler = new NetworkHandler();

            void options(AccessTokenManagementOptions o)
            {
                o.Client.Clients.Add("test1", new PasswordTokenRequest
                {
                    Address = "https://test1",
                    ClientId = "test1",
                    UserName = "test1",
                    Password = "test1"
                });

                o.Client.Clients.Add("test2", new PasswordTokenRequest
                {
                    Address = "https://test2",
                    ClientId = "test2",
                    UserName = "test2",
                    Password = "test2"
                });
            }

            var service = Setup.Collection(options, handler)
                .BuildServiceProvider()
                .GetRequiredService<IAccessTokenManagementService>();


            var result = await service.GetClientAccessTokenAsync("test1");
            handler.Address.Should().Be(new Uri("https://test1"));

            result = await service.GetClientAccessTokenAsync("test2");
            handler.Address.Should().Be(new Uri("https://test2"));
        }
    }
}