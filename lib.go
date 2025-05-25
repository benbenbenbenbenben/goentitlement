package goentitlment

import (
	"encoding/json"

	cedar "github.com/cedar-policy/cedar-go"
)

const policyCedar = `permit (
	principal in UserGroup::"jane_friends",
	action == Action::"view",
	resource == Photo::"VacationPhoto94.jpg"
  );
`

const entitiesJSON = `[
  {
    "uid": {"type": "PublicKey", "id": "ed25519:MCowBQYDK2VwAQoDIQD1OW5HC2WYL8nN0fOtWJNM8qtqQ1kwKvl+oUv7OVz5+g=="},
    "attrs": {},
    "parents": [{"type": "UserGroup", "id": "jane_friends"}]
  },
  {
    "uid": {"type": "UserGroup", "id": "jane_friends"},
    "attrs": {},
    "parents": []
  },
  {
    "uid": {"type": "Photo", "id": "VacationPhoto94.jpg"},
    "attrs": {},
    "parents": []
  }
]`

func Allow() (bool, error) {
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(policyCedar)); err != nil {
		return false, err
	}

	ps := cedar.NewPolicySet()
	ps.Add("policy0", &policy)

	var entities cedar.EntityMap
	if err := json.Unmarshal([]byte(entitiesJSON), &entities); err != nil {
		return false, err
	}

	req := cedar.Request{
		Principal: cedar.NewEntityUID("PublicKey", "ed25519:MCowBQYDK2VwAQoDIQD1OW5HC2WYL8nN0fOtWJNM8qtqQ1kwKvl+oUv7OVz5+g=="),
		Action:    cedar.NewEntityUID("Action", "view"),
		Resource:  cedar.NewEntityUID("Photo", "VacationPhoto94.jpg"),
		Context: cedar.NewRecord(cedar.RecordMap{
			"demoRequest": cedar.True,
		}),
	}

	ok, _ := cedar.Authorize(ps, &entities, req)

	return bool(ok), nil
}
