package htstat

import (
	"net/http"
)

type HttpStatusTbl struct {
	Ok        HttpStatusMsg `toml:",omitempty"`
	Unauth    HttpStatusMsg `toml:",omitempty"`
	Forbidden HttpStatusMsg `toml:",omitempty"`
	Nopath    HttpStatusMsg `toml:",omitempty"`
	Nouser    HttpStatusMsg `toml:",omitempty"`
}

func (st *HttpStatusTbl) SetDefault() {
	st.Ok.SetDefault(http.StatusOK, "Authorized")
	st.Unauth.SetDefault(http.StatusUnauthorized, "Not authenticated")
	st.Forbidden.SetDefault(http.StatusForbidden, "Forbidden")
	st.Nopath.SetDefault(http.StatusForbidden, "No path header")
	st.Nouser.SetDefault(http.StatusForbidden, "No user header")
}

func (st *HttpStatusTbl) IsValid() bool {
	return st.Ok.IsValid() &&
		st.Unauth.IsValid() &&
		st.Forbidden.IsValid() &&
		st.Nopath.IsValid() &&
		st.Nouser.IsValid()
}

type HttpStatusMsg struct {
	Code    int    `toml:",omitempty"`
	Message string `toml:",omitempty"`
}

func (em *HttpStatusMsg) IsValid() bool {
	return em.Code >= 100 && em.Code < 600
}

func (em *HttpStatusMsg) SetDefault(code int, msg string) {
	if em.Code == 0 {
		em.Code = code
	}
	if em.Message == "" {
		em.Message = msg
	}
}

func (em *HttpStatusMsg) Error(w http.ResponseWriter) {
	http.Error(w, em.Message, em.Code)
}
