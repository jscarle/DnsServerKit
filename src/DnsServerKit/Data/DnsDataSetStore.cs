namespace DnsServerKit.Data;

/// <summary>Publishes immutable DNS dataset snapshots to concurrent readers.</summary>
public sealed class DnsDataSetStore
{
    private DnsDataSet _current;

    public DnsDataSet Current => Volatile.Read(ref _current);

    public DnsDataSetStore(DnsDataSet initialDataSet)
    {
        ArgumentNullException.ThrowIfNull(initialDataSet);
        _current = initialDataSet;
    }

    public void Replace(DnsDataSet dataSet)
    {
        ArgumentNullException.ThrowIfNull(dataSet);
        Volatile.Write(ref _current, dataSet);
    }
}
