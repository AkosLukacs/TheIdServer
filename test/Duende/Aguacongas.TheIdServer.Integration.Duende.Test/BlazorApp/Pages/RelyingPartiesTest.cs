﻿// Project: Aguafrommars/TheIdServer
// Copyright (c) 2022 @Olivier Lefebvre
using Aguacongas.IdentityServer.EntityFramework.Store;
using Aguacongas.IdentityServer.Store.Entity;
using System.Threading.Tasks;
using Xunit;
using RelyingPartiesPage = Aguacongas.TheIdServer.BlazorApp.Pages.RelyingParties.RelyingParties;

namespace Aguacongas.TheIdServer.IntegrationTest.BlazorApp.Pages
{
    [Collection(BlazorAppCollection.Name)]
    public class RelyingPartiesTest : EntitiesPageTestBase<RelyingParty, RelyingPartiesPage>
    {
        public override string Entities => "relyingparties";
        public RelyingPartiesTest(TheIdServerFactory factory)
            : base(factory)
        {
        }

        protected override Task PopulateList()
        {
            return DbActionAsync<ConfigurationDbContext>(context =>
            {
                context.RelyingParties.Add(new RelyingParty
                {
                    Id = GenerateId(),
                    Description = "filtered",
                    TokenType = GenerateId(),
                    DigestAlgorithm = GenerateId(),
                    SignatureAlgorithm = GenerateId()
                });

                return context.SaveChangesAsync();
            });
        }
    }
}
