/*
* Honeytrap Agent
* Copyright (C) 2016-2017 DutchSec (https://dutchsec.com/)
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU Affero General Public License version 3 as published by the
* Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
* details.
*
* You should have received a copy of the GNU Affero General Public License
* version 3 along with this program in the file "LICENSE".  If not, see
* <http://www.gnu.org/licenses/agpl-3.0.txt>.
*
* See https://honeytrap.io/ for more details. All requests should be sent to
* licensing@honeytrap.io
*
* The interactive user interfaces in modified source and object code versions
* of this program must display Appropriate Legal Notices, as required under
* Section 5 of the GNU Affero General Public License version 3.
*
* In accordance with Section 7(b) of the GNU Affero General Public License version 3,
* these Appropriate Legal Notices must retain the display of the "Powered by
* Honeytrap" logo and retain the original copyright notice. If the display of the
* logo is not reasonably feasible for technical reasons, the Appropriate Legal Notices
* must display the words "Powered by Honeytrap" and retain the original copyright notice.
 */
package server

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"

	_ "net/http/pprof"

	"net"

	"github.com/rs/xid"
)

type OptionFn func(*Agent) error

func HomeDir() string {
	var err error
	var usr *user.User
	if usr, err = user.Current(); err != nil {
		panic(err)
	}

	p := path.Join(usr.HomeDir, ".honeytrap")

	_, err = os.Stat(p)

	switch {
	case err == nil:
		break
	case os.IsNotExist(err):
		if err = os.Mkdir(p, 0755); err != nil {
			panic(err)
		}
	default:
		panic(err)
	}

	return p
}

func WithKey(key string) OptionFn {
	v, _ := hex.DecodeString(key)

	return func(h *Agent) error {
		h.RemoteKey = v
		return nil
	}
}

func WithName(name string) OptionFn {
	return func(h *Agent) error {
		h.Name = name
		return nil
	}
}

func WithServer(server string) OptionFn {
	host, port, _ := net.SplitHostPort(server)
	if port == "" {
		port = "1337"
	}

	return func(h *Agent) error {
		h.Server = net.JoinHostPort(host, port)
		return nil
	}
}

func expand(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}

	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, path[1:]), nil
}

func WithDataDir(s string) (OptionFn, error) {
	var err error

	p, err := expand(s)
	if err != nil {
		return nil, err
	}

	p, err = filepath.Abs(p)
	_, err = os.Stat(p)

	switch {
	case err == nil:
		break
	case os.IsNotExist(err):
		if err = os.Mkdir(p, 0755); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	return func(b *Agent) error {
		b.dataDir = p
		return nil
	}, nil
}

func WithToken() OptionFn {
	return func(h *Agent) error {
		uid := xid.New().String()

		p := h.dataDir
		p = path.Join(p, "token")

		if _, err := os.Stat(p); os.IsNotExist(err) {
			ioutil.WriteFile(p, []byte(uid), 0600)
		} else if err != nil {
			// other error
			panic(err)
		} else if data, err := ioutil.ReadFile(p); err == nil {
			uid = string(data)
		} else {
			panic(err)
		}

		h.token = uid
		return nil
	}
}
