package landhorse

import (
	"context"
	"errors"
	"fmt"

	"github.com/chigopher/pathlib"
	"go.yaml.in/yaml/v4"

	"github.com/wrouesnel/landhorse/pkg/backend"
	"github.com/wrouesnel/landhorse/pkg/secretservice"
)

// settings implements ui.Settings: it applies changes to the running backends and saves
// them to the configuration file.
type settings struct {
	path      *pathlib.Path
	config    *EntrypointConfig
	passwords *secretservice.Group
}

// KeyringGroupings implements ui.Settings.
func (s *settings) KeyringGroupings() []backend.AttributeGrouping {
	result := make([]backend.AttributeGrouping, 0, len(s.config.Passwords.Groups))
	for _, g := range s.config.Passwords.Groups {
		result = append(result, backend.AttributeGrouping{Attribute: g.Attribute, Title: g.Title})
	}
	return result
}

// SetKeyringGroupings implements ui.Settings.
func (s *settings) SetKeyringGroupings(groupings []backend.AttributeGrouping) error {
	groups := make([]GroupConfig, 0, len(groupings))
	for _, g := range groupings {
		groups = append(groups, GroupConfig{Attribute: g.Attribute, Title: g.Title})
	}
	if err := saveConfigValue(s.path, []string{"passwords", "groups"}, groups); err != nil {
		return fmt.Errorf("saving %s: %w", s.path, err)
	}
	s.config.Passwords.Groups = groups
	if s.passwords != nil {
		s.passwords.SetGroupings(groupings)
	}
	return nil
}

// KeyringAttributes implements ui.Settings.
func (s *settings) KeyringAttributes(ctx context.Context) (map[string]int, error) {
	if s.passwords == nil {
		return nil, errors.New("keyrings are disabled")
	}
	return s.passwords.AttributeNames(ctx)
}

// saveConfigValue sets the value at keys in the YAML configuration file, creating the file
// and any missing mappings. The file is edited as a YAML document tree, so the user's
// comments and other settings are kept. An empty slice value removes the key.
func saveConfigValue(path *pathlib.Path, keys []string, value any) error {
	var doc yaml.Node
	if exists, _ := path.Exists(); exists {
		data, err := path.ReadFile()
		if err != nil {
			return err
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return err
		}
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		// An empty file or a bare "{}".
		*root = yaml.Node{Kind: yaml.MappingNode}
	}

	var valueNode yaml.Node
	encoded, err := yaml.Marshal(value)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(encoded, &valueNode); err != nil {
		return err
	}
	remove := valueNode.Kind == 0 || len(valueNode.Content) == 0 ||
		(valueNode.Content[0].Kind == yaml.SequenceNode && len(valueNode.Content[0].Content) == 0)

	node := root
	for i, key := range keys {
		last := i == len(keys)-1
		idx := -1
		for j := 0; j+1 < len(node.Content); j += 2 {
			if node.Content[j].Value == key {
				idx = j
				break
			}
		}
		if last {
			switch {
			case remove && idx >= 0:
				node.Content = append(node.Content[:idx], node.Content[idx+2:]...)
			case remove:
			case idx >= 0:
				node.Content[idx+1] = valueNode.Content[0]
			default:
				node.Content = append(node.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Value: key}, valueNode.Content[0])
			}
			break
		}
		if idx < 0 || node.Content[idx+1].Kind != yaml.MappingNode {
			child := &yaml.Node{Kind: yaml.MappingNode}
			if idx < 0 {
				node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, child)
			} else {
				node.Content[idx+1] = child
			}
			node = child
			continue
		}
		node = node.Content[idx+1]
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	if err := path.Parent().MkdirAll(); err != nil {
		return err
	}
	return path.WriteFileMode(out, 0o644)
}
