using Aguacongas.TheIdServer.BlazorApp.Models;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using System.Collections.Generic;

namespace Aguacongas.TheIdServer.BlazorApp.Services
{
    public class AddressListAuthorizationMessageHandler : AuthorizationMessageHandler
    {
        public AddressListAuthorizationMessageHandler(IEnumerable<string> authorizedUrls, 
            IAccessTokenProvider provider, 
            NavigationManager navigation) : base(provider, navigation)
        {
            ConfigureHandler(authorizedUrls);
        }
    }
}
