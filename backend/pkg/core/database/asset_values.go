package database

import (
	"encoding/json"
	"strings"
	"time"
)

type AssetValue struct {
	Value  string   `json:"value"`
	Source []string `json:"source,omitempty"`
}

type legacyAssetRecord struct {
	TaskID    string    `json:"task_id"`
	Version   int       `json:"version"`
	Email     []string  `json:"email,omitempty"`
	IDCard    []string  `json:"id_card,omitempty"`
	Phone     []string  `json:"phone,omitempty"`
	IPURL     []string  `json:"ip_url,omitempty"`
	APIRoot   []string  `json:"apiroot,omitempty"`
	APIRouter []string  `json:"apirouter,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (record *AssetRecord) UnmarshalJSON(data []byte) error {
	type assetRecordBase struct {
		TaskID    string    `json:"task_id"`
		Version   int       `json:"version"`
		CreatedAt time.Time `json:"created_at"`
	}

	var base assetRecordBase
	if err := json.Unmarshal(data, &base); err != nil {
		return err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	record.TaskID = base.TaskID
	record.Version = base.Version
	record.CreatedAt = base.CreatedAt
	record.Email = decodeAssetValues(rawValue(raw, "email"))
	record.IDCard = decodeAssetValues(rawValue(raw, "id_card", "idCard"))
	record.Phone = decodeAssetValues(rawValue(raw, "phone"))
	record.IPURL = decodeAssetValues(rawValue(raw, "ip_url", "ipUrl"))
	record.APIRoot = decodeAssetValues(rawValue(raw, "apiroot", "api_root", "apiRoot", "apiRoots"))
	record.APIRouter = decodeAssetValues(rawValue(raw, "apirouter", "api_router", "apiRouter", "apiRoutes"))
	return nil
}

func rawValue(values map[string]json.RawMessage, keys ...string) json.RawMessage {
	for _, key := range keys {
		if raw, ok := values[key]; ok {
			return raw
		}
	}
	return nil
}

func decodeAssetValues(data json.RawMessage) []AssetValue {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}

	var objectItems []struct {
		Value  string          `json:"value"`
		Source json.RawMessage `json:"source"`
	}
	if err := json.Unmarshal(data, &objectItems); err == nil {
		result := make([]AssetValue, 0, len(objectItems))
		for _, item := range objectItems {
			value := strings.TrimSpace(item.Value)
			if value == "" {
				continue
			}
			result = append(result, AssetValue{
				Value:  value,
				Source: decodeAssetSources(item.Source),
			})
		}
		return MergeAssetValues(result)
	}

	var stringItems []string
	if err := json.Unmarshal(data, &stringItems); err == nil {
		result := make([]AssetValue, 0, len(stringItems))
		for _, item := range stringItems {
			value := strings.TrimSpace(item)
			if value == "" {
				continue
			}
			result = append(result, AssetValue{Value: value})
		}
		return MergeAssetValues(result)
	}

	var singleString string
	if err := json.Unmarshal(data, &singleString); err == nil {
		value := strings.TrimSpace(singleString)
		if value == "" {
			return nil
		}
		return []AssetValue{{Value: value}}
	}

	return nil
}

func decodeAssetSources(data json.RawMessage) []string {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}

	var many []string
	if err := json.Unmarshal(data, &many); err == nil {
		return uniqueTrimmedStrings(many)
	}

	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		return uniqueTrimmedStrings([]string{one})
	}

	return nil
}

func MergeAssetValues(groups ...[]AssetValue) []AssetValue {
	if len(groups) == 0 {
		return nil
	}

	merged := make([]AssetValue, 0)
	indexByValue := make(map[string]int)

	for _, group := range groups {
		for _, item := range group {
			value := strings.TrimSpace(item.Value)
			if value == "" {
				continue
			}

			sources := uniqueTrimmedStrings(item.Source)
			if index, exists := indexByValue[value]; exists {
				merged[index].Source = uniqueTrimmedStrings(append(merged[index].Source, sources...))
				continue
			}

			indexByValue[value] = len(merged)
			merged = append(merged, AssetValue{
				Value:  value,
				Source: sources,
			})
		}
	}

	return merged
}

func NewAssetValues(items []string, sources ...string) []AssetValue {
	values := make([]AssetValue, 0, len(items))
	normalizedSources := uniqueTrimmedStrings(sources)
	for _, item := range items {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		values = append(values, AssetValue{
			Value:  value,
			Source: append([]string(nil), normalizedSources...),
		})
	}
	return MergeAssetValues(values)
}

func uniqueTrimmedStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func flattenAssetValues(items []AssetValue) []string {
	if len(items) == 0 {
		return nil
	}

	values := make([]string, 0, len(items))
	for _, item := range items {
		value := strings.TrimSpace(item.Value)
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	return uniqueTrimmedStrings(values)
}

func toLegacyAssetRecord(asset AssetRecord) legacyAssetRecord {
	return legacyAssetRecord{
		TaskID:    asset.TaskID,
		Version:   asset.Version,
		Email:     flattenAssetValues(asset.Email),
		IDCard:    flattenAssetValues(asset.IDCard),
		Phone:     flattenAssetValues(asset.Phone),
		IPURL:     flattenAssetValues(asset.IPURL),
		APIRoot:   flattenAssetValues(asset.APIRoot),
		APIRouter: flattenAssetValues(asset.APIRouter),
		CreatedAt: asset.CreatedAt,
	}
}
