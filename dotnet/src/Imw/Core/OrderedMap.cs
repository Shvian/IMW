namespace Imw.Core;

/// <summary>An insertion-ordered dictionary (Python dict / OrderedDict): assigning to an existing
/// key keeps its place, removing a key and adding it again moves it to the end.</summary>
public sealed class OrderedMap<TKey, TValue> : IEnumerable<KeyValuePair<TKey, TValue>>
{
    readonly List<TKey> _keys = new();
    readonly Dictionary<TKey, TValue> _map;

    public OrderedMap() { _map = new(); }
    public OrderedMap(IEqualityComparer<TKey> comparer) { _map = new(comparer); }

    public TValue this[TKey key]
    {
        get => _map[key];
        set
        {
            if (!_map.ContainsKey(key)) _keys.Add(key);
            _map[key] = value;
        }
    }

    public int Count => _keys.Count;
    public IReadOnlyList<TKey> Keys => _keys;
    public IEnumerable<TValue> Values => _keys.Select(k => _map[k]);
    public bool ContainsKey(TKey key) => _map.ContainsKey(key);
    public bool TryGetValue(TKey key, out TValue value) => _map.TryGetValue(key, out value);
    public TValue GetValueOrDefault(TKey key, TValue dflt = default) => _map.TryGetValue(key, out var v) ? v : dflt;

    /// <summary>dict.setdefault(key, make())</summary>
    public TValue GetOrAdd(TKey key, Func<TValue> make)
    {
        if (_map.TryGetValue(key, out var v)) return v;
        v = make();
        this[key] = v;
        return v;
    }

    public bool Remove(TKey key)
    {
        if (!_map.Remove(key)) return false;
        _keys.Remove(key);
        return true;
    }

    public IEnumerator<KeyValuePair<TKey, TValue>> GetEnumerator()
    {
        foreach (var k in _keys.ToList()) yield return new(k, _map[k]);
    }

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
}
