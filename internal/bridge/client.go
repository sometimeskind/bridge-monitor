package bridge

import (
	"context"
	"strings"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/sometimeskind/bridge-monitor/internal/pb"
)

// GetUsers returns the current bridge user list.
func (c *Client) GetUsers(ctx context.Context) ([]*pb.User, error) {
	resp, err := c.Bridge.GetUserList(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return resp.GetUsers(), nil
}

// FindUser locates the user matching the given login identifier (the email from
// the credentials secret), comparing case-insensitively against the username and
// all addresses. Returns nil if no user matches.
func FindUser(users []*pb.User, login string) *pb.User {
	login = strings.ToLower(strings.TrimSpace(login))
	for _, u := range users {
		if strings.ToLower(u.GetUsername()) == login {
			return u
		}
		for _, addr := range u.GetAddresses() {
			if strings.ToLower(addr) == login {
				return u
			}
		}
	}
	return nil
}
