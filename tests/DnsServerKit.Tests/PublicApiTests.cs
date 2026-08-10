using Xunit;

namespace DnsServerKit.Tests;

public sealed class PublicApiTests
{
    [Fact]
    public void Assembly_WhenExportedTypesAreInspected_MatchesSupportedSdkSurface()
    {
        string[] expectedTypeNames =
        [
            "DnsServerKit.DnsServer",
            "DnsServerKit.DnsServerOptions",
            "DnsServerKit.Parameters.DnsClass",
            "DnsServerKit.Records.ARecord",
            "DnsServerKit.Records.ARecordSet",
            "DnsServerKit.Records.AaaaRecord",
            "DnsServerKit.Records.AaaaRecordSet",
            "DnsServerKit.Records.CnameRecord",
            "DnsServerKit.Records.CnameRecordSet",
            "DnsServerKit.Records.MxRecord",
            "DnsServerKit.Records.MxRecordSet",
            "DnsServerKit.Records.NsRecord",
            "DnsServerKit.Records.NsRecordSet",
            "DnsServerKit.Records.PtrRecord",
            "DnsServerKit.Records.PtrRecordSet",
            "DnsServerKit.Records.RecordSet",
            "DnsServerKit.Records.SoaRecord",
            "DnsServerKit.Records.SoaRecordSet",
            "DnsServerKit.Records.TxtRecord",
            "DnsServerKit.Records.TxtRecordSet",
            "DnsServerKit.Zones.DnsZone",
            "DnsServerKit.Zones.DnsZoneBuilder",
            "DnsServerKit.Zones.DnsZoneSet",
            "DnsServerKit.Zones.DnsZoneSetBuilder",
            "DnsServerKit.Zones.DnsZoneStore",
        ];
        var exportedTypes = typeof(DnsServer).Assembly.GetExportedTypes();
        var exportedTypeNames = new string[exportedTypes.Length];
        for (var typeIndex = 0; typeIndex < exportedTypes.Length; typeIndex++)
            exportedTypeNames[typeIndex] = exportedTypes[typeIndex].FullName!;

        Array.Sort(exportedTypeNames, StringComparer.Ordinal);

        Assert.Equal(expectedTypeNames, exportedTypeNames);
    }
}
