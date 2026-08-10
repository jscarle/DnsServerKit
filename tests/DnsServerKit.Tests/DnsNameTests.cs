using DnsServerKit.Internal.Protocol;
using Xunit;

namespace DnsServerKit.Tests;

public sealed class DnsNameTests
{
    [Fact]
    public void Constructor_WhenGivenPresentationNames_WritesCanonicalWireNames()
    {
        (string Name, byte[] WireBytes)[] testCases =
        [
            (string.Empty, [0]),
            (".", [0]),
            ("Example.COM.", [7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 3, (byte)'c', (byte)'o', (byte)'m', 0]),
            (@"a\.b.\000\255", [3, (byte)'a', (byte)'.', (byte)'b', 2, 0, 255, 0]),
        ];

        foreach (var testCase in testCases)
        {
            var name = new DnsName(testCase.Name);
            Assert.Equal(testCase.WireBytes, name.WireBytes.ToArray());
        }
    }

    [Fact]
    public void Equals_WhenNamesDifferOnlyByAsciiCase_ReturnsTrue()
    {
        var first = new DnsName("Example.COM");
        var second = new DnsName("example.com.");

        Assert.Equal(first, second);
        Assert.Equal(first.GetHashCode(), second.GetHashCode());
    }

    [Fact]
    public void Constructor_WhenNameIsInvalid_ThrowsFormatException()
    {
        var nameExceeding255Octets = string.Join(
            '.',
            new string('a', 63),
            new string('b', 63),
            new string('c', 63),
            new string('d', 62));
        string[] invalidNames =
        [
            "example..com",
            new string('a', 64),
            nameExceeding255Octets,
            @"\256",
            "example\\",
        ];

        foreach (var invalidName in invalidNames)
            Assert.Throws<FormatException>(() => new DnsName(invalidName));
    }

}
