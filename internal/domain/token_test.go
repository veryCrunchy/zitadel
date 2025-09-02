package domain

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddAudScopeToAudience(t *testing.T) {
	ctx := context.Background()
	
	type args struct {
		audience []string
		scopes   []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "empty scopes",
			args: args{
				audience: []string{"existing"},
				scopes:   []string{},
			},
			want: []string{"existing"},
		},
		{
			name: "non-matching scopes",
			args: args{
				audience: []string{"existing"},
				scopes:   []string{"openid", "profile"},
			},
			want: []string{"existing"},
		},
		{
			name: "ProjectIDScope pattern",
			args: args{
				audience: []string{"existing"},
				scopes:   []string{ProjectIDScope + "myproject" + AudSuffix},
			},
			want: []string{"existing", "myproject"},
		},
		{
			name: "client:aud pattern should replace audience",
			args: args{
				audience: []string{"existing", "other"},
				scopes:   []string{"myclient" + AudSuffix},
			},
			want: []string{"myclient"},
		},
		{
			name: "multiple client:aud patterns should use last one",
			args: args{
				audience: []string{"existing"},
				scopes:   []string{"client1" + AudSuffix, "client2" + AudSuffix},
			},
			want: []string{"client2"},
		},
		{
			name: "mixed ProjectIDScope and client:aud - client:aud should win",
			args: args{
				audience: []string{"existing"},
				scopes:   []string{ProjectIDScope + "myproject" + AudSuffix, "myclient" + AudSuffix},
			},
			want: []string{"myclient"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AddAudScopeToAudience(ctx, tt.args.audience, tt.args.scopes)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRoleOrgIDsFromScope(t *testing.T) {
	type args struct {
		scopes []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "nil",
			args: args{nil},
			want: nil,
		},
		{
			name: "unrelated scope",
			args: args{[]string{"foo", "bar"}},
			want: nil,
		},
		{
			name: "orgID role scope",
			args: args{[]string{OrgRoleIDScope + "123"}},
			want: []string{"123"},
		},
		{
			name: "mixed scope",
			args: args{[]string{"foo", OrgRoleIDScope + "123"}},
			want: []string{"123"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RoleOrgIDsFromScope(tt.args.scopes)
			assert.Equal(t, tt.want, got)
		})
	}
}
