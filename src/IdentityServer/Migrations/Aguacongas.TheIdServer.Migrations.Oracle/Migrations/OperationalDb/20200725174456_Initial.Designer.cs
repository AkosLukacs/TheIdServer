﻿// Project: Aguafrommars/TheIdServer
// Copyright (c) 2022 @Olivier Lefebvre
using System;
using Aguacongas.IdentityServer.EntityFramework.Store;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Aguacongas.TheIdServer.Oracle.Migrations.OperationalDb
{
    [DbContext(typeof(OperationalDbContext))]
    [Migration("20200725174456_Initial")]
    partial class Initial
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "3.1.6");

            modelBuilder.Entity("Aguacongas.IdentityServer.Store.Entity.AuthorizationCode", b =>
                {
                    b.Property<string>("Id")
                        .HasColumnType("nvarchar2(450)");

                    b.Property<string>("ClientId")
                        .IsRequired()
                        .HasColumnType("nclob");

                    b.Property<DateTime>("CreatedAt")
                        .HasColumnType("timestamp");

                    b.Property<string>("Data")
                        .HasColumnType("nclob");

                    b.Property<DateTime?>("Expiration")
                        .HasColumnType("timestamp");

                    b.Property<DateTime?>("ModifiedAt")
                        .HasColumnType("timestamp");

                    b.Property<string>("SessionId")
                        .HasColumnType("nclob");

                    b.Property<string>("UserId")
                        .HasColumnType("nvarchar2(200)")
                        .HasMaxLength(200);

                    b.HasKey("Id");

                    b.ToTable("AuthorizationCodes");
                });

            modelBuilder.Entity("Aguacongas.IdentityServer.Store.Entity.DeviceCode", b =>
                {
                    b.Property<string>("Id")
                        .HasColumnType("nvarchar2(450)");

                    b.Property<string>("ClientId")
                        .IsRequired()
                        .HasColumnType("nclob");

                    b.Property<string>("Code")
                        .HasColumnType("nvarchar2(200)")
                        .HasMaxLength(200);

                    b.Property<DateTime>("CreatedAt")
                        .HasColumnType("timestamp");

                    b.Property<string>("Data")
                        .HasColumnType("nclob");

                    b.Property<DateTime>("Expiration")
                        .HasColumnType("timestamp");

                    b.Property<DateTime?>("ModifiedAt")
                        .HasColumnType("timestamp");

                    b.Property<string>("SubjectId")
                        .HasColumnType("nvarchar2(200)")
                        .HasMaxLength(200);

                    b.Property<string>("UserCode")
                        .HasColumnType("nvarchar2(200)")
                        .HasMaxLength(200);

                    b.HasKey("Id");

                    b.ToTable("DeviceCodes");
                });

            modelBuilder.Entity("Aguacongas.IdentityServer.Store.Entity.OneTimeToken", b =>
                {
                    b.Property<string>("Id")
                        .HasColumnType("nvarchar2(450)");

                    b.Property<string>("ClientId")
                        .IsRequired()
                        .HasColumnType("nclob");

                    b.Property<DateTime>("CreatedAt")
                        .HasColumnType("timestamp");

                    b.Property<string>("Data")
                        .HasColumnType("nclob");

                    b.Property<DateTime?>("Expiration")
                        .HasColumnType("timestamp");

                    b.Property<DateTime?>("ModifiedAt")
                        .HasColumnType("timestamp");

                    b.Property<string>("SessionId")
                        .HasColumnType("nclob");

                    b.Property<string>("UserId")
                        .HasColumnType("nvarchar2(200)")
                        .HasMaxLength(200);

                    b.HasKey("Id");

                    b.ToTable("OneTimeTokens");
                });

            modelBuilder.Entity("Aguacongas.IdentityServer.Store.Entity.ReferenceToken", b =>
                {
                    b.Property<string>("Id")
                        .HasColumnType("nvarchar2(450)");

                    b.Property<string>("ClientId")
                        .IsRequired()
                        .HasColumnType("nclob");

                    b.Property<DateTime>("CreatedAt")
                        .HasColumnType("timestamp");

                    b.Property<string>("Data")
                        .HasColumnType("nclob");

                    b.Property<DateTime?>("Expiration")
                        .HasColumnType("timestamp");

                    b.Property<DateTime?>("ModifiedAt")
                        .HasColumnType("timestamp");

                    b.Property<string>("SessionId")
                        .HasColumnType("nclob");

                    b.Property<string>("UserId")
                        .HasColumnType("nvarchar2(200)")
                        .HasMaxLength(200);

                    b.HasKey("Id");

                    b.ToTable("ReferenceTokens");
                });

            modelBuilder.Entity("Aguacongas.IdentityServer.Store.Entity.RefreshToken", b =>
                {
                    b.Property<string>("Id")
                        .HasColumnType("nvarchar2(450)");

                    b.Property<string>("ClientId")
                        .IsRequired()
                        .HasColumnType("nclob");

                    b.Property<DateTime>("CreatedAt")
                        .HasColumnType("timestamp");

                    b.Property<string>("Data")
                        .HasColumnType("nclob");

                    b.Property<DateTime?>("Expiration")
                        .HasColumnType("timestamp");

                    b.Property<DateTime?>("ModifiedAt")
                        .HasColumnType("timestamp");

                    b.Property<string>("SessionId")
                        .HasColumnType("nclob");

                    b.Property<string>("UserId")
                        .HasColumnType("nvarchar2(200)")
                        .HasMaxLength(200);

                    b.HasKey("Id");

                    b.ToTable("RefreshTokens");
                });

            modelBuilder.Entity("Aguacongas.IdentityServer.Store.Entity.UserConsent", b =>
                {
                    b.Property<string>("Id")
                        .HasColumnType("nvarchar2(450)");

                    b.Property<string>("ClientId")
                        .IsRequired()
                        .HasColumnType("nclob");

                    b.Property<DateTime>("CreatedAt")
                        .HasColumnType("timestamp");

                    b.Property<string>("Data")
                        .HasColumnType("nclob");

                    b.Property<DateTime?>("Expiration")
                        .HasColumnType("timestamp");

                    b.Property<DateTime?>("ModifiedAt")
                        .HasColumnType("timestamp");

                    b.Property<string>("SessionId")
                        .HasColumnType("nclob");

                    b.Property<string>("UserId")
                        .IsRequired()
                        .HasColumnType("nvarchar2(200)")
                        .HasMaxLength(200);

                    b.HasKey("Id");

                    b.ToTable("UserConstents");
                });
#pragma warning restore 612, 618
        }
    }
}
