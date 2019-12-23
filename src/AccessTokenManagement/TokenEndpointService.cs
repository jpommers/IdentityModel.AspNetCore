// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace IdentityModel.AspNetCore.AccessTokenManagement
{
    /// <summary>
    /// Implements token endpoint operations using IdentityModel
    /// </summary>
    public class TokenEndpointService : ITokenEndpointService
    {
        private readonly AccessTokenManagementOptions _accessTokenManagementOptions;

        private readonly IOptionsMonitor<OpenIdConnectOptions> _oidcOptions;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly HttpClient _httpClient;

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="accessTokenManagementOptions"></param>
        /// <param name="oidcOptions"></param>
        /// <param name="schemeProvider"></param>
        /// <param name="httpClientFactory"></param>
        public TokenEndpointService(
            IOptions<AccessTokenManagementOptions> accessTokenManagementOptions,
            IOptionsMonitor<OpenIdConnectOptions> oidcOptions,
            IAuthenticationSchemeProvider schemeProvider,
            IHttpClientFactory httpClientFactory)
        {
            _accessTokenManagementOptions = accessTokenManagementOptions.Value;

            _oidcOptions = oidcOptions;
            _schemeProvider = schemeProvider;
            _httpClient = httpClientFactory.CreateClient(AccessTokenManagementDefaults.BackChannelHttpClientName);
        }

        /// <inheritdoc/>
        public async Task<TokenResponse> RequestClientAccessToken(string clientName = AccessTokenManagementDefaults.DefaultTokenClientName)
        {
            PasswordTokenRequest requestDetails;
            if (!_accessTokenManagementOptions.Client.Clients.TryGetValue(clientName, out requestDetails))
            {
                throw new InvalidOperationException($"No access token client configuration found for client: {clientName}");
            }
            return await _httpClient.RequestPasswordTokenAsync(requestDetails);
        }

        /// <inheritdoc/>
        public async Task<TokenResponse> RefreshUserAccessTokenAsync(string refreshToken)
        {
            var (options, configuration) = await GetOpenIdConnectSettingsAsync(_accessTokenManagementOptions.User.Scheme);

            return await _httpClient.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = configuration.TokenEndpoint,

                ClientId = options.ClientId,
                ClientSecret = options.ClientSecret,
                RefreshToken = refreshToken
            });
        }

        /// <inheritdoc/>
        public async Task<TokenRevocationResponse> RevokeRefreshTokenAsync(string refreshToken)
        {
            var (options, configuration) = await GetOpenIdConnectSettingsAsync(_accessTokenManagementOptions.User.Scheme);

            return await _httpClient.RevokeTokenAsync(new TokenRevocationRequest
            {
                Address = configuration.AdditionalData[OidcConstants.Discovery.RevocationEndpoint].ToString(),
                ClientId = options.ClientId,
                ClientSecret = options.ClientSecret,
                Token = refreshToken,
                TokenTypeHint = OidcConstants.TokenTypes.RefreshToken
            });
        }

        internal async Task<(OpenIdConnectOptions options, OpenIdConnectConfiguration configuration)> GetOpenIdConnectSettingsAsync(string schemeName)
        {
            OpenIdConnectOptions options;

            if (string.IsNullOrWhiteSpace(schemeName))
            {
                var scheme = await _schemeProvider.GetDefaultChallengeSchemeAsync();

                if (scheme is null)
                {
                    throw new InvalidOperationException("No OpenID Connect authentication scheme configured for getting client configuration. Either set the scheme name explicitly or set the default challenge scheme");
                }

                options = _oidcOptions.Get(scheme.Name);
            }
            else
            {
                options = _oidcOptions.Get(schemeName);
            }

            OpenIdConnectConfiguration configuration;
            try
            {
                configuration = await options.ConfigurationManager.GetConfigurationAsync(default);
            }
            catch (Exception e)
            {
                throw new InvalidOperationException($"Unable to load OpenID configuration for configured scheme: {e.Message}");
            }

            return (options, configuration);
        }
    }
}