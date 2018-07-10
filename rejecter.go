package jose

type Rejecter interface {
	Reject(map[string]interface{}) bool
}

type RejecterFunc func(map[string]interface{}) bool

func (r RejecterFunc) Reject(v map[string]interface{}) bool { return r(v) }

type FixedRejecter bool

func (f FixedRejecter) Reject(_ map[string]interface{}) bool { return bool(f) }
