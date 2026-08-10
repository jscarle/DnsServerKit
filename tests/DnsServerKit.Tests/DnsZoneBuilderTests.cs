using DnsServerKit.Internal.Protocol;
using DnsServerKit.Parameters;
using DnsServerKit.Records;
using DnsServerKit.Zones;
using Xunit;

namespace DnsServerKit.Tests;

public sealed class DnsZoneBuilderTests
{
    [Fact]
    public void Build_WhenConvenienceMethodsAreUsed_CreatesTypedRecordSetModels()
    {
        var nameServers = new List<string> { "ns1.example.com", "ns2.example.com" };
        var pointerTargets = new List<string> { "target1.example.com", "target2.example.com" };
        var builder = new DnsZoneBuilder("example.com");
        builder.AddSoaRecord(
            300,
            "ns1.example.com",
            "hostmaster@example.com",
            2026081001,
            3600,
            600,
            1_209_600,
            300);
        builder.AddNsRecord(600, nameServers);
        builder.AddARecord(0, "@", "192.0.2.1", "192.0.2.2");
        builder.AddPtrRecord(60, "pointer", pointerTargets);

        nameServers.Add("ns3.example.com");
        pointerTargets.Clear();
        var zone = builder.Build();

        var startOfAuthorityRecordSet = Assert.IsType<SoaRecordSet>(zone.RecordSets.ElementAt(0));
        var nameServerRecordSet = Assert.IsType<NsRecordSet>(zone.RecordSets.ElementAt(1));
        var addressRecordSet = Assert.IsType<ARecordSet>(zone.RecordSets.ElementAt(2));
        var pointerRecordSet = Assert.IsType<PtrRecordSet>(zone.RecordSets.ElementAt(3));
        Assert.Equal(300U, startOfAuthorityRecordSet.Ttl);
        Assert.Equal("hostmaster@example.com", startOfAuthorityRecordSet.Record.ResponsibleMailbox);
        Assert.Equal(600U, nameServerRecordSet.Ttl);
        Assert.Equal(2, nameServerRecordSet.Count);
        Assert.Equal(0U, addressRecordSet.Ttl);
        Assert.Equal(2, addressRecordSet.Count);
        Assert.Equal(60U, pointerRecordSet.Ttl);
        Assert.Equal(2, pointerRecordSet.Count);
    }

    [Fact]
    public void Build_WhenAllSupportedModelsAreAdded_ExposesFlatTypedRecordSets()
    {
        var builder = CreateBuilder();
        builder.AddRecordSet(new ARecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = [new ARecord { Address = "192.0.2.1" }],
        });
        builder.AddRecordSet(new PtrRecordSet
        {
            Name = "pointer",
            Ttl = 60,
            Records = [new PtrRecord { Target = "target.example" }],
        });

        var zone = builder.Build();

        Assert.Equal("example.com", zone.Name);
        Assert.Equal(DnsClass.Internet, zone.Class);
        var startOfAuthorityRecordSet = Assert.IsType<SoaRecordSet>(zone.RecordSets.ElementAt(0));
        var nameServerRecordSet = Assert.IsType<NsRecordSet>(zone.RecordSets.ElementAt(1));
        var addressRecordSet = Assert.IsType<ARecordSet>(zone.RecordSets.ElementAt(2));
        var pointerRecordSet = Assert.IsType<PtrRecordSet>(zone.RecordSets.ElementAt(3));
        Assert.Equal("ns1.example.com", startOfAuthorityRecordSet.Record.PrimaryNameServer);
        Assert.Equal("hostmaster@example.com", startOfAuthorityRecordSet.Record.ResponsibleMailbox);
        Assert.Equal("ns1.example.com", nameServerRecordSet.Records.Single().NameServer);
        Assert.Equal("192.0.2.1", addressRecordSet.Records.Single().Address);
        Assert.Equal("target.example", pointerRecordSet.Records.Single().Target);
    }

    [Fact]
    public void AddRecordSet_WhenCallerCollectionChanges_PreservesBuilderOwnedCopy()
    {
        var records = new List<ARecord> { new() { Address = "192.0.2.1" } };
        var builder = CreateBuilder();
        builder.AddRecordSet(new ARecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = records,
        });

        records.Add(new ARecord { Address = "192.0.2.2" });
        var zone = builder.Build();
        var recordSet = zone.RecordSets.OfType<ARecordSet>().Single();

        Assert.Single(recordSet.Records);
        Assert.Equal("192.0.2.1", recordSet.Records.Single().Address);
    }

    [Fact]
    public void AddRecordSet_WhenValuesHaveAlternatePresentation_NormalizesWriterOwnedValues()
    {
        var builder = new DnsZoneBuilder("example.com");
        builder.AddRecordSet(new SoaRecordSet
        {
            Name = "@",
            Ttl = 300,
            Record = CreateSoaRecord("DNS Admin <first.last@EXAMPLE.COM>"),
        });
        builder.AddNsRecord(300, "ns1.example.com");
        builder.AddARecord(300, "@", "3232236033");

        var zone = builder.Build();
        var startOfAuthorityRecordSet = zone.RecordSets.OfType<SoaRecordSet>().Single();
        var addressRecordSet = zone.RecordSets.OfType<ARecordSet>().Single();

        Assert.Equal("first.last@example.com", startOfAuthorityRecordSet.Record.ResponsibleMailbox);
        Assert.Equal("192.168.2.1", addressRecordSet.Records.Single().Address);
    }

    [Fact]
    public void AddRecordSet_WhenCollectionIsEmptyOrContainsNull_ThrowsArgumentException()
    {
        var builder = new DnsZoneBuilder("example.com");
        var emptyRecordSet = new ARecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = [],
        };
        var nullRecordSet = new PtrRecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = new PtrRecord[] { null! },
        };

        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(emptyRecordSet));
        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(nullRecordSet));
    }

    [Fact]
    public void AddRecordSet_WhenRequiredRuntimeValueIsNull_ThrowsArgumentException()
    {
        var builder = new DnsZoneBuilder("example.com");
        var addressRecordSet = new ARecordSet
        {
            Name = null!,
            Ttl = 300,
            Records = [new ARecord { Address = "192.0.2.1" }],
        };
        var nameServerRecordSet = new NsRecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = [new NsRecord { NameServer = null! }],
        };
        var startOfAuthorityRecordSet = new SoaRecordSet
        {
            Name = "@",
            Ttl = 300,
            Record = null!,
        };

        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(addressRecordSet));
        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(nameServerRecordSet));
        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(startOfAuthorityRecordSet));
    }

    [Fact]
    public void AddRecordSet_WhenValuesAreInvalid_ThrowsArgumentException()
    {
        var builder = new DnsZoneBuilder("example.com");

        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(new ARecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = [new ARecord { Address = "2001:db8::1" }],
        }));
        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(new PtrRecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = [new PtrRecord { Target = "invalid..example" }],
        }));
        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(new NsRecordSet
        {
            Name = "delegation",
            Ttl = 300,
            Records = [new NsRecord { NameServer = "ns1.example.com" }],
        }));
        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(new SoaRecordSet
        {
            Name = "@",
            Ttl = 300,
            Record = CreateSoaRecord("hostmaster.example.com"),
        }));
        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(new SoaRecordSet
        {
            Name = "not-the-apex",
            Ttl = 300,
            Record = CreateSoaRecord("hostmaster@example.com"),
        }));
    }

    [Fact]
    public void AddRecordSet_WhenValuesContainCanonicalDuplicates_ThrowsArgumentException()
    {
        var builder = new DnsZoneBuilder("example.com");

        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(new ARecordSet
        {
            Name = "@",
            Ttl = 300,
            Records =
            [
                new ARecord { Address = "192.0.2.1" },
                new ARecord { Address = "192.0.2.1" },
            ],
        }));
        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(new PtrRecordSet
        {
            Name = "@",
            Ttl = 300,
            Records =
            [
                new PtrRecord { Target = "Target.Example" },
                new PtrRecord { Target = "target.example." },
            ],
        }));
        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(new NsRecordSet
        {
            Name = "@",
            Ttl = 300,
            Records =
            [
                new NsRecord { NameServer = "Ns1.Example" },
                new NsRecord { NameServer = "ns1.example." },
            ],
        }));
    }

    [Fact]
    public void AddRecordSet_WhenOwnerAndTypeAlreadyExist_ThrowsWithoutReplacingOriginal()
    {
        var builder = CreateBuilder();
        builder.AddRecordSet(new ARecordSet
        {
            Name = "www",
            Ttl = 300,
            Records = [new ARecord { Address = "192.0.2.1" }],
        });

        Assert.Throws<InvalidOperationException>(() => builder.AddRecordSet(new ARecordSet
        {
            Name = "WWW",
            Ttl = 999,
            Records = [new ARecord { Address = "192.0.2.2" }],
        }));

        var zone = builder.Build();
        var recordSet = zone.RecordSets.OfType<ARecordSet>().Single();
        Assert.Equal(300U, recordSet.Ttl);
        Assert.Equal("192.0.2.1", recordSet.Records.Single().Address);
    }

    [Fact]
    public void AddRecordSet_WhenOneRecordIsInvalid_DoesNotPartiallyMutateBuilder()
    {
        var builder = CreateBuilder();
        Assert.Throws<ArgumentException>(() => builder.AddRecordSet(new ARecordSet
        {
            Name = "@",
            Ttl = 300,
            Records =
            [
                new ARecord { Address = "192.0.2.1" },
                new ARecord { Address = "invalid" },
            ],
        }));

        builder.AddRecordSet(new ARecordSet
        {
            Name = "@",
            Ttl = 0,
            Records = [new ARecord { Address = "192.0.2.1" }],
        });

        Assert.Equal(3, builder.Build().RecordSets.Count);
    }

    [Fact]
    public void Build_WhenSoaOrNameServersAreMissing_ThrowsInvalidOperationException()
    {
        var emptyBuilder = new DnsZoneBuilder("empty.example");
        Assert.Throws<InvalidOperationException>(() => emptyBuilder.Build());

        var withoutNameServers = new DnsZoneBuilder("no-ns.example");
        withoutNameServers.AddRecordSet(new SoaRecordSet
        {
            Name = "@",
            Ttl = 300,
            Record = CreateSoaRecord("hostmaster@no-ns.example", "ns1.no-ns.example"),
        });
        Assert.Throws<InvalidOperationException>(() => withoutNameServers.Build());

        var withoutSoa = new DnsZoneBuilder("no-soa.example");
        withoutSoa.AddRecordSet(new NsRecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = [new NsRecord { NameServer = "ns1.no-soa.example" }],
        });
        Assert.Throws<InvalidOperationException>(() => withoutSoa.Build());
    }

    [Fact]
    public void AddRecordSet_WhenOwnerIsRelative_ResolvesAgainstApexAndRootZone()
    {
        var builder = CreateBuilder();
        builder.AddRecordSet(new ARecordSet
        {
            Name = "www",
            Ttl = 300,
            Records = [new ARecord { Address = "192.0.2.1" }],
        });
        var store = CreateStore(builder.Build());

        var rootBuilder = new DnsZoneBuilder(".");
        rootBuilder.AddRecordSet(new SoaRecordSet
        {
            Name = "@",
            Ttl = 300,
            Record = CreateSoaRecord("hostmaster@example", "ns1.example"),
        });
        rootBuilder.AddRecordSet(new NsRecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = [new NsRecord { NameServer = "ns1.example" }],
        });
        rootBuilder.AddRecordSet(new ARecordSet
        {
            Name = "host.example",
            Ttl = 300,
            Records = [new ARecord { Address = "192.0.2.2" }],
        });
        var rootStore = CreateStore(rootBuilder.Build());

        Assert.True(store.TryGet(new DnsName("www.example.com"), 1, 1, out _));
        Assert.True(rootStore.TryGet(new DnsName("host.example"), 1, 1, out _));
    }

    private static DnsZoneBuilder CreateBuilder()
    {
        var builder = new DnsZoneBuilder("example.com");
        builder.AddRecordSet(new SoaRecordSet
        {
            Name = "@",
            Ttl = 300,
            Record = CreateSoaRecord("hostmaster@example.com"),
        });
        builder.AddRecordSet(new NsRecordSet
        {
            Name = "@",
            Ttl = 300,
            Records = [new NsRecord { NameServer = "ns1.example.com" }],
        });

        return builder;
    }

    private static SoaRecord CreateSoaRecord(
        string responsibleMailbox,
        string primaryNameServer = "ns1.example.com")
    {
        return new SoaRecord
        {
            PrimaryNameServer = primaryNameServer,
            ResponsibleMailbox = responsibleMailbox,
            Serial = 1,
            Refresh = 3600,
            Retry = 600,
            Expire = 1_209_600,
            Minimum = 300,
        };
    }

    private static DnsZoneStore CreateStore(DnsZone zone)
    {
        var builder = new DnsZoneSetBuilder();
        builder.Load(zone);
        var zoneSet = builder.Build();
        var store = new DnsZoneStore();
        store.Load(zoneSet);

        return store;
    }
}
