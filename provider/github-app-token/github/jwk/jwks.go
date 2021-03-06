package jwk

import "encoding/json"

type Set struct {
	Keys []Key
}

func ParseSet(data []byte) (*Set, error) {
	var keys struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, err
	}

	list := make([]Key, 0, len(keys.Keys))
	for _, raw := range keys.Keys {
		if key, err := ParseKey(raw); err == nil {
			list = append(list, key)
			// Ignore keys that cannot be parsed.
		}
	}
	return &Set{
		Keys: list,
	}, nil
}

func (set *Set) Find(kid string) (key Key, found bool) {
	for _, k := range set.Keys {
		if k.KeyID() == kid {
			return k, true
		}
	}
	return nil, false
}
