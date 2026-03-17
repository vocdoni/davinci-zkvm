package poseidon2

import (
	"reflect"
	"testing"
)

func TestPermuteWidth8IsDeterministic(t *testing.T) {
	input := [8]uint64{0, 1, 2, 3, 4, 5, 6, 7}
	got1 := PermuteWidth8(input)
	got2 := PermuteWidth8(input)
	if got1 != got2 {
		t.Fatalf("PermuteWidth8 must be deterministic: %v vs %v", got1, got2)
	}
	if got1 == input {
		t.Fatalf("PermuteWidth8 must not leave the state unchanged")
	}
}

func TestHashWidth8IsDeterministic(t *testing.T) {
	input := []uint64{1, 2, 3, 4, 5, 6}
	got1 := HashWidth8(input, 4)
	got2 := HashWidth8(input, 4)
	if !reflect.DeepEqual(got1, got2) {
		t.Fatalf("HashWidth8 must be deterministic: %v vs %v", got1, got2)
	}
}

func TestPermuteWidth16MatchesZiskReferenceVector(t *testing.T) {
	input := [16]uint64{}
	for i := range input {
		input[i] = uint64(i)
	}
	got := PermuteWidth16(input)
	want := [16]uint64{
		9639188652563994454,
		12273372933164734616,
		2905147255612444119,
		17581461329934617288,
		14390794100096760072,
		5468485695976078057,
		2832370985856357627,
		1116111836864400812,
		14997632823506024332,
		3976503894892102369,
		14874978986912301676,
		12458748982184310703,
		103345454961107931,
		3354965064850558444,
		14413825288474057217,
		4214638127285300968,
	}
	if got != want {
		t.Fatalf("PermuteWidth16 mismatch\n got: %v\nwant: %v", got, want)
	}
}
