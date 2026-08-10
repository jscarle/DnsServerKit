using Xunit;

namespace DnsServerKit.Tests;

public sealed class PublicApiTests
{
    [Fact]
    public void Assembly_WhenExportedTypesAreInspected_MatchesSupportedSdkSurface()
    {
        string[] expectedTypeNames =
        [
            "DnsServerKit.Data.DnsRecordSet",
            "DnsServerKit.Data.DnsZone",
            "DnsServerKit.Data.DnsZoneBuilder",
            "DnsServerKit.Data.DnsZoneSet",
            "DnsServerKit.Data.DnsZoneSetBuilder",
            "DnsServerKit.Data.DnsZoneStore",
            "DnsServerKit.DnsServer",
            "DnsServerKit.DnsServerOptions",
            "DnsServerKit.Parameters.DnsClass",
            "DnsServerKit.ResourceRecords.ARecord",
            "DnsServerKit.ResourceRecords.ARecordSet",
            "DnsServerKit.ResourceRecords.NsRecord",
            "DnsServerKit.ResourceRecords.NsRecordSet",
            "DnsServerKit.ResourceRecords.PtrRecord",
            "DnsServerKit.ResourceRecords.PtrRecordSet",
            "DnsServerKit.ResourceRecords.SoaRecord",
            "DnsServerKit.ResourceRecords.SoaRecordSet",
        ];
        var exportedTypes = typeof(DnsServer).Assembly.GetExportedTypes();
        var exportedTypeNames = new string[exportedTypes.Length];
        for (var typeIndex = 0; typeIndex < exportedTypes.Length; typeIndex++)
            exportedTypeNames[typeIndex] = exportedTypes[typeIndex].FullName!;

        Array.Sort(exportedTypeNames, StringComparer.Ordinal);

        Assert.Equal(expectedTypeNames, exportedTypeNames);
    }
}
