package crawl

// enrichRequestBlueprintSymbolsFromModules resolves symbols that the local
// block could not define by issuing on-demand queries against the module
// resolver. Lookup count is budgeted per analysis input.
func enrichRequestBlueprintSymbolsFromModules(index *jsRequestSymbolIndex, resolver *jsModuleResolver, file string, offset int, candidates []string) {
	if resolver == nil || index == nil || len(candidates) == 0 {
		return
	}
	lookups := 0
	for _, name := range candidates {
		if _, ok := index.definitions[name]; ok {
			continue
		}
		if lookups >= maxModuleSymbolLookups {
			return
		}
		lookups++
		hits := resolver.lookupSymbol(name, file, offset, 1)
		if len(hits) == 0 {
			continue
		}
		hit := hits[0]
		index.definitions[name] = jsRequestSymbolDefinition{
			Name:      hit.Name,
			Kind:      hit.Kind,
			Value:     hit.Value,
			ValueExpr: hit.ValueExpr,
			Fields:    hit.Fields,
		}
	}
}
