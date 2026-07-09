//go:build darwin && automicvault

package credentials

import "github.com/zalando/go-keyring"

type mockKeyringBackend struct {
	store map[string]map[string]string
	err   error
}

func mockKeyringInit() {
	keyringBackendOverride = &mockKeyringBackend{}
}

func mockKeyringInitWithError(err error) {
	keyringBackendOverride = &mockKeyringBackend{err: err}
}

func (m *mockKeyringBackend) Set(service, account, password string) error {
	if m.err != nil {
		return m.err
	}
	if m.store == nil {
		m.store = make(map[string]map[string]string)
	}
	if m.store[service] == nil {
		m.store[service] = make(map[string]string)
	}
	m.store[service][account] = password
	return nil
}

func (m *mockKeyringBackend) Get(service, account string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	if accounts, ok := m.store[service]; ok {
		if password, ok := accounts[account]; ok {
			return password, nil
		}
	}
	return "", keyring.ErrNotFound
}

func (m *mockKeyringBackend) Delete(service, account string) error {
	if m.err != nil {
		return m.err
	}
	if accounts, ok := m.store[service]; ok {
		if _, ok := accounts[account]; ok {
			delete(accounts, account)
			return nil
		}
	}
	return keyring.ErrNotFound
}

func (m *mockKeyringBackend) DeleteAll(service string) error {
	if m.err != nil {
		return m.err
	}
	delete(m.store, service)
	return nil
}
