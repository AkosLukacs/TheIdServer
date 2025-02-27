﻿// Project: Aguafrommars/TheIdServer
// Copyright (c) 2022 @Olivier Lefebvre
using Aguacongas.IdentityServer.Store;
using Aguacongas.IdentityServer.Store.Entity;
using System.Threading;
using System.Threading.Tasks;

namespace Aguacongas.TheIdServer.BlazorApp.Services
{
    public interface IReadOnlyCultureStore
    {
        Task<PageResponse<Culture>> GetAsync(PageRequest pageRequest, CancellationToken cancellationToken = default);
    }
}