package database

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type ScanDataStore interface {
	ListJSResources(taskID string, versions ...int) ([]JSResource, error)
	ListAPIResources(taskID string, versions ...int) ([]APIResource, error)
	ListProtocolTraces(taskID string, versions ...int) ([]ProtocolTraceRecord, error)
}

type esScanDataStore struct{}

func (esScanDataStore) ListJSResources(taskID string, versions ...int) ([]JSResource, error) {
	return QueryJSByTaskID(taskID, versions...)
}

func (esScanDataStore) ListAPIResources(taskID string, versions ...int) ([]APIResource, error) {
	return QueryAPIResourcesByTaskID(taskID, versions...)
}

func (esScanDataStore) ListProtocolTraces(taskID string, versions ...int) ([]ProtocolTraceRecord, error) {
	return QueryProtocolTracesByTaskID(taskID, versions...)
}

var defaultScanDataStore ScanDataStore = esScanDataStore{}

func GetScanDataStore() ScanDataStore {
	return defaultScanDataStore
}

func SetScanDataStore(store ScanDataStore) {
	if store == nil {
		defaultScanDataStore = esScanDataStore{}
		return
	}
	defaultScanDataStore = store
}

type MemoryScanDataStore struct {
	mu             sync.RWMutex
	jsResources    map[string][]JSResource
	apiResources   map[string][]APIResource
	protocolTraces map[string][]ProtocolTraceRecord
}

func NewMemoryScanDataStore() *MemoryScanDataStore {
	return &MemoryScanDataStore{
		jsResources:    make(map[string][]JSResource),
		apiResources:   make(map[string][]APIResource),
		protocolTraces: make(map[string][]ProtocolTraceRecord),
	}
}

func (s *MemoryScanDataStore) AddJSResources(taskID string, resources []JSResource) {
	if s == nil || strings.TrimSpace(taskID) == "" || len(resources) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jsResources[taskID] = append(s.jsResources[taskID], resources...)
}

func (s *MemoryScanDataStore) AddAPIResources(taskID string, resources []APIResource) {
	if s == nil || strings.TrimSpace(taskID) == "" || len(resources) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiResources[taskID] = append(s.apiResources[taskID], resources...)
}

func (s *MemoryScanDataStore) AddProtocolTraces(taskID string, traces []ProtocolTraceRecord) {
	if s == nil || strings.TrimSpace(taskID) == "" || len(traces) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.protocolTraces[taskID] = append(s.protocolTraces[taskID], traces...)
}

func (s *MemoryScanDataStore) ListJSResources(taskID string, versions ...int) ([]JSResource, error) {
	if s == nil {
		return nil, fmt.Errorf("memory scan data store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return filterResourcesByVersion(s.jsResources[taskID], versions...), nil
}

func (s *MemoryScanDataStore) ListAPIResources(taskID string, versions ...int) ([]APIResource, error) {
	if s == nil {
		return nil, fmt.Errorf("memory scan data store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return filterResourcesByVersion(s.apiResources[taskID], versions...), nil
}

func (s *MemoryScanDataStore) ListProtocolTraces(taskID string, versions ...int) ([]ProtocolTraceRecord, error) {
	if s == nil {
		return nil, fmt.Errorf("memory scan data store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	traces := filterResourcesByVersion(s.protocolTraces[taskID], versions...)
	sort.Slice(traces, func(i, j int) bool {
		return traces[i].CreatedAt.After(traces[j].CreatedAt)
	})
	return traces, nil
}

func filterResourcesByVersion[T interface{ GetVersion() int }](items []T, versions ...int) []T {
	if len(items) == 0 {
		return nil
	}
	if len(versions) == 0 || versions[0] <= 0 {
		result := make([]T, len(items))
		copy(result, items)
		return result
	}
	version := versions[0]
	result := make([]T, 0, len(items))
	for _, item := range items {
		if item.GetVersion() == version {
			result = append(result, item)
		}
	}
	return result
}

func (r JSResource) GetVersion() int          { return r.Version }
func (r APIResource) GetVersion() int         { return r.Version }
func (r ProtocolTraceRecord) GetVersion() int { return r.Version }
