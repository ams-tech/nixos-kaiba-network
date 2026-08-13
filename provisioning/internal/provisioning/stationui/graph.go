package stationui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	TransitionGraphSchemaVersion = "provisioning.kaiba.network/station-demo-transition-graph/v1alpha1"
	RuntimeConfigSchemaVersion   = "provisioning.kaiba.network/station-demo-runtime/v1alpha1"
)

// TransitionGraph is the finite, revision-independent representation of the
// mock Machine. The GitHub Pages client consumes this generated graph instead
// of maintaining a second workflow implementation in JavaScript.
type TransitionGraph struct {
	SchemaVersion      string                         `json:"schema_version"`
	StateSchemaVersion string                         `json:"state_schema_version"`
	DefaultNode        string                         `json:"default_node"`
	Nodes              map[string]TransitionGraphNode `json:"nodes"`
}

type TransitionGraphNode struct {
	State       State             `json:"state"`
	Transitions map[Action]string `json:"transitions"`
}

type graphPath struct {
	nodeID  string
	actions []Action
}

// GenerateTransitionGraph explores every action exposed by the authoritative
// Go mock state machine. State revisions are assigned by the runtime client,
// so they are set to zero in node templates to keep the graph finite.
func GenerateTransitionGraph() (TransitionGraph, error) {
	rootMachine, err := NewMockMachine(ScenarioHappyPath)
	if err != nil {
		return TransitionGraph{}, err
	}
	rootState := canonicalGraphState(rootMachine.Snapshot())
	rootID, err := graphStateID(rootState)
	if err != nil {
		return TransitionGraph{}, err
	}

	graph := TransitionGraph{
		SchemaVersion:      TransitionGraphSchemaVersion,
		StateSchemaVersion: StateSchemaVersion,
		DefaultNode:        rootID,
		Nodes: map[string]TransitionGraphNode{
			rootID: {State: rootState, Transitions: map[Action]string{}},
		},
	}
	paths := map[string][]Action{rootID: nil}
	queue := []graphPath{{nodeID: rootID}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		_, state, err := replayGraphPath(current.actions)
		if err != nil {
			return TransitionGraph{}, fmt.Errorf("replay node %s: %w", current.nodeID, err)
		}
		canonical := canonicalGraphState(state)
		actualID, err := graphStateID(canonical)
		if err != nil {
			return TransitionGraph{}, err
		}
		if actualID != current.nodeID {
			return TransitionGraph{}, fmt.Errorf("replayed node changed identity: got %s, want %s", actualID, current.nodeID)
		}

		node := graph.Nodes[current.nodeID]
		for _, action := range state.AllowedActions {
			machine, before, err := replayGraphPath(current.actions)
			if err != nil {
				return TransitionGraph{}, fmt.Errorf("replay before %q: %w", action, err)
			}
			next, err := machine.Apply(ActionRequest{Action: action, ExpectedRevision: before.Revision})
			if err != nil {
				return TransitionGraph{}, fmt.Errorf("apply exposed action %q: %w", action, err)
			}
			next = canonicalGraphState(next)
			nextID, err := graphStateID(next)
			if err != nil {
				return TransitionGraph{}, err
			}
			node.Transitions[action] = nextID

			if _, exists := paths[nextID]; exists {
				continue
			}
			nextActions := append(append([]Action(nil), current.actions...), action)
			paths[nextID] = nextActions
			graph.Nodes[nextID] = TransitionGraphNode{State: next, Transitions: map[Action]string{}}
			queue = append(queue, graphPath{nodeID: nextID, actions: nextActions})
		}
		graph.Nodes[current.nodeID] = node
	}

	return graph, nil
}

func replayGraphPath(actions []Action) (*Machine, State, error) {
	machine, err := NewMockMachine(ScenarioHappyPath)
	if err != nil {
		return nil, State{}, err
	}
	state := machine.Snapshot()
	for _, action := range actions {
		state, err = machine.Apply(ActionRequest{Action: action, ExpectedRevision: state.Revision})
		if err != nil {
			return nil, State{}, fmt.Errorf("apply %q: %w", action, err)
		}
	}
	return machine, state, nil
}

func canonicalGraphState(state State) State {
	canonical := cloneState(state)
	canonical.Revision = 0
	return canonical
}

func graphStateID(state State) (string, error) {
	encoded, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("encode graph state: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
