package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/shidoh/wgfleet/internal/controller/clientcfg"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// DeviceManager is the device registry the panel drives. *keybroker.Broker
// satisfies it.
type DeviceManager interface {
	Masters() []string
	ListDevices(ctx context.Context) ([]domain.ClientDevice, error)
	GetDevice(ctx context.Context, id string) (domain.ClientDevice, error)
	CreateDevice(ctx context.Context, name string) (domain.ClientDevice, error)
	RenameDevice(ctx context.Context, id, name string) error
	RotateDeviceToken(ctx context.Context, id string) (domain.ClientDevice, error)
	DeleteDevice(ctx context.Context, id string) error
	AttachCredential(ctx context.Context, kind domain.CredentialKind, masterID, ref, deviceID string) error
	DetachCredential(ctx context.Context, kind domain.CredentialKind, masterID, ref string) error
	IssueWGClientForDevice(ctx context.Context, masterID, deviceID string) (domain.WGClient, error)
	IssueVLESSClientForDevice(ctx context.Context, masterID, deviceID string) (domain.VLESSClient, error)
	// ClientMasterMeta feeds the profile download the same routing metadata the
	// portal's source gets.
	ClientMasterMeta(ctx context.Context, masterID string) (domain.ClientMasterMeta, error)
}

// SetDevices wires the device registry (ADR-0035). Optional, like SetRoller:
// without it the section is absent (404).
func (h *Handler) SetDevices(d DeviceManager) { h.devices = d }

type deviceRow struct {
	ID, Name, PageURL, SubURL string
	Creds                     []domain.DeviceCredential
	Fetches                   []fetchView
}

// credChoice is one selectable credential; LiveLink marks an AWG credential whose
// own portal link still works — attaching it kills that link.
type credChoice struct {
	Ref, Name string
	LiveLink  bool
}

type masterSlots struct {
	Master           string
	AWG, VLESS       *domain.DeviceCredential
	FreeAWG, FreeVLS []credChoice
}

type devicesData struct {
	Title, User, Flash, FlashOK, CSRF string
	NodeCount                         int
	PortalBase                        string
	Devices                           []deviceRow
	// ShowFetches adds the "Last download" column.
	ShowFetches bool
	Device      *deviceRow
	Slots       []masterSlots
	// MultiMaster prefixes each connection badge in the list with its master;
	// with one master the prefix repeats the same name on every row.
	MultiMaster bool
}

// connCellView is one transport on one master on the device page: the credential
// holding the slot, or the credentials that could fill it.
type connCellView struct {
	DeviceID, CSRF, Master, Kind string
	Label, Slug, Href            string
	Cred                         *domain.DeviceCredential
	Free                         []credChoice
}

func connCell(d devicesData, s masterSlots, kind string) connCellView {
	v := connCellView{DeviceID: d.Device.ID, CSRF: d.CSRF, Master: s.Master, Kind: kind}
	k := domain.CredentialKind(kind)
	v.Label, v.Slug = credLabel(k), credSlug(k)
	if k == domain.CredentialVLESS {
		v.Cred, v.Free, v.Href = s.VLESS, s.FreeVLS, "/nodes/"+s.Master+"/clients"
	} else {
		v.Cred, v.Free = s.AWG, s.FreeAWG
		if s.AWG != nil {
			v.Href = "/nodes/" + s.Master + "/wg-clients#client-" + s.AWG.Ref
		}
	}
	return v
}

// credLabel and credSlug reuse the transport badge of the fleet page: AWG blue,
// VLESS (REALITY underneath) violet — the same colour means the same thing.
func credLabel(k domain.CredentialKind) string {
	if k == domain.CredentialVLESS {
		return "VLESS"
	}
	return "AWG"
}

func credSlug(k domain.CredentialKind) string {
	if k == domain.CredentialVLESS {
		return "reality"
	}
	return "amnezia"
}

// deviceLinks are the two URLs a person is handed, built from the configured
// public portal URL only: a link from the panel's own host would point at the
// operator's console.
func (h *Handler) deviceLinks(d domain.ClientDevice) (page, sub string) {
	if h.portalBase == "" {
		return "", ""
	}
	page = h.portalBase + "/c/" + d.Token
	return page, page + "/mihomo"
}

func (h *Handler) devicesData(w http.ResponseWriter, r *http.Request, title string) devicesData {
	user, _ := h.currentUser(r)
	return devicesData{Title: title, User: user, CSRF: h.csrf, NodeCount: h.fleetCount(r.Context()),
		PortalBase: h.portalBase, Flash: h.takeFlash(w, r), FlashOK: h.takeFlashOK(w, r),
		MultiMaster: h.devices != nil && len(h.devices.Masters()) > 1}
}

func (h *Handler) handleDevices(w http.ResponseWriter, r *http.Request) {
	if h.devices == nil {
		http.NotFound(w, r)
		return
	}
	devs, err := h.devices.ListDevices(r.Context())
	if err != nil {
		httpError(w, "list devices", err)
		return
	}
	data := h.devicesData(w, r, "Devices")
	data.ShowFetches = h.fetches != nil
	fetches := h.deviceFetches(r.Context())
	for _, d := range devs {
		page, sub := h.deviceLinks(d)
		data.Devices = append(data.Devices, deviceRow{ID: d.ID, Name: d.Name, PageURL: page, SubURL: sub,
			Creds: d.Credentials, Fetches: fetches[d.ID]})
	}
	if data.Slots, err = h.freeSlots(r.Context(), devs, domain.ClientDevice{}); err != nil {
		httpError(w, "list credentials", err)
		return
	}
	h.render(w, h.devicesTmpl, "layout", data)
}

// freeSlots lists, per master, the device's slots and the credentials that could
// fill them — only those attached to no device: the store refuses the others,
// and offering them would invite the mistake.
func (h *Handler) freeSlots(ctx context.Context, all []domain.ClientDevice, dev domain.ClientDevice) ([]masterSlots, error) {
	attached := map[string]bool{}
	for _, d := range all {
		for _, c := range d.Credentials {
			attached[string(c.Kind)+"|"+c.MasterID+"|"+c.Ref] = true
		}
	}
	var out []masterSlots
	for _, m := range h.devices.Masters() {
		s := masterSlots{Master: m}
		if c, ok := dev.Credential(domain.CredentialAWG, m); ok {
			s.AWG = &c
		}
		if c, ok := dev.Credential(domain.CredentialVLESS, m); ok {
			s.VLESS = &c
		}
		wgs, err := h.renderer.ListWGClients(ctx, m)
		if err != nil {
			return nil, err
		}
		for _, c := range wgs {
			if !attached["awg|"+m+"|"+c.ID] {
				s.FreeAWG = append(s.FreeAWG, credChoice{Ref: c.ID, Name: c.Name, LiveLink: !c.LegacyLinkRetired})
			}
		}
		vls, err := h.renderer.ListVLESSClients(ctx, m)
		if err != nil {
			return nil, err
		}
		for _, c := range vls {
			if !attached["vless|"+m+"|"+c.Name] {
				s.FreeVLS = append(s.FreeVLS, credChoice{Ref: c.Name, Name: c.Name})
			}
		}
		out = append(out, s)
	}
	return out, nil
}

func (h *Handler) handleDevice(w http.ResponseWriter, r *http.Request) {
	if h.devices == nil {
		http.NotFound(w, r)
		return
	}
	dev, err := h.devices.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		httpError(w, "load device", err)
		return
	}
	all, err := h.devices.ListDevices(r.Context())
	if err != nil {
		httpError(w, "list devices", err)
		return
	}
	data := h.devicesData(w, r, "Device — "+dev.Name)
	page, sub := h.deviceLinks(dev)
	data.Device = &deviceRow{ID: dev.ID, Name: dev.Name, PageURL: page, SubURL: sub, Creds: dev.Credentials}
	if data.Slots, err = h.freeSlots(r.Context(), all, dev); err != nil {
		httpError(w, "list credentials", err)
		return
	}
	h.render(w, h.deviceTmpl, "layout", data)
}

// liveLinkCredentials names the AWG credentials among choices (master -> ref)
// whose personal link still works — the ones an attach would silently kill.
func (h *Handler) liveLinkCredentials(ctx context.Context, choices map[string]string) ([]string, error) {
	var names []string
	for master, ref := range choices {
		if ref == "" || ref == "new" {
			continue
		}
		wgs, err := h.renderer.ListWGClients(ctx, master)
		if err != nil {
			return nil, err
		}
		for _, c := range wgs {
			if c.ID == ref && !c.LegacyLinkRetired {
				names = append(names, c.Name+" on "+master)
			}
		}
	}
	return names, nil
}

func formHidden(r *http.Request) []hiddenField {
	var out []hiddenField
	for k, vs := range r.PostForm {
		if k == "csrf_token" || k == "confirm" {
			continue
		}
		for _, v := range vs {
			out = append(out, hiddenField{Name: k, Value: v})
		}
	}
	return out
}

func (h *Handler) handleDeviceCreate(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	if h.devices == nil {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if !validClientName(name) {
		h.redirectErr(w, r, "/devices", "create device", errors.New("name must be 1-64 chars of letters, digits, '-', '_' or '.'"))
		return
	}
	awgChoices := map[string]string{}
	for _, m := range h.devices.Masters() {
		awgChoices[m] = r.PostFormValue("awg_" + m)
	}
	live, err := h.liveLinkCredentials(r.Context(), awgChoices)
	if err != nil {
		h.redirectErr(w, r, "/devices", "create device", err)
		return
	}
	if len(live) > 0 && h.needsConfirmation(w, r, confirmView{
		Title: "Attach credentials", Heading: "Attach " + strings.Join(live, ", ") + "?",
		Consequence: "Each credential's own personal link stops working for good the moment it joins the device. " +
			"Whoever uses that link must switch to the device's link. The tunnel already configured keeps working.",
		Action: "/devices/create", ConfirmLabel: "Create and attach", CancelHref: "/devices",
		Hidden: formHidden(r),
	}) {
		return
	}
	dev, err := h.devices.CreateDevice(r.Context(), name)
	if err != nil {
		h.redirectErr(w, r, "/devices", "create device", deviceActionError(err, name, "", ""))
		return
	}
	h.audit(r, "create device", "device", name)
	dest := "/devices/" + dev.ID
	// The device exists from here on; a slot that fails is reported on the
	// device's own page, where just that slot can be retried.
	for _, m := range h.devices.Masters() {
		for _, kind := range []domain.CredentialKind{domain.CredentialAWG, domain.CredentialVLESS} {
			if err := h.fillSlot(r, dev.ID, kind, m, r.PostFormValue(string(kind)+"_"+m)); err != nil {
				h.redirectErr(w, r, dest, "set up "+string(kind)+" on "+m, deviceActionError(err, name, m, kind))
				return
			}
		}
	}
	h.setFlashOK(w, "Created "+name+" — hand out its subscription link below.")
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// fillSlot applies one slot choice: "" leaves it empty, "new" issues a credential
// already attached, anything else attaches that existing credential.
func (h *Handler) fillSlot(r *http.Request, deviceID string, kind domain.CredentialKind, master, choice string) error {
	switch choice {
	case "":
		return nil
	case "new":
		var err error
		if kind == domain.CredentialAWG {
			_, err = h.devices.IssueWGClientForDevice(r.Context(), master, deviceID)
		} else {
			_, err = h.devices.IssueVLESSClientForDevice(r.Context(), master, deviceID)
		}
		return err
	default:
		return h.devices.AttachCredential(r.Context(), kind, master, choice, deviceID)
	}
}

func (h *Handler) handleDeviceAttach(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	if h.devices == nil {
		http.NotFound(w, r)
		return
	}
	id := r.PathValue("id")
	dest := "/devices/" + id
	kind, ok := parseKind(r.PostFormValue("kind"))
	master, ref := r.PostFormValue("master"), r.PostFormValue("ref")
	if !ok || !h.isMaster(master) {
		h.redirectErr(w, r, dest, "attach credential", errors.New("unknown credential kind or master"))
		return
	}
	if kind == domain.CredentialAWG {
		live, err := h.liveLinkCredentials(r.Context(), map[string]string{master: ref})
		if err != nil {
			h.redirectErr(w, r, dest, "attach credential", err)
			return
		}
		if len(live) > 0 && h.needsConfirmation(w, r, confirmView{
			Title: "Attach credential", Heading: "Attach " + live[0] + "?",
			Consequence: "Its own personal link stops working for good. Whoever uses it must switch to this device's link.",
			Action:      dest + "/attach", ConfirmLabel: "Attach", CancelHref: dest, Hidden: formHidden(r),
		}) {
			return
		}
	}
	if err := h.fillSlot(r, id, kind, master, ref); err != nil {
		h.redirectErr(w, r, dest, "attach credential", deviceActionError(err, "", master, kind))
		return
	}
	h.audit(r, "attach credential", "device", id, "kind", string(kind), "master", master)
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (h *Handler) handleDeviceDetach(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	if h.devices == nil {
		http.NotFound(w, r)
		return
	}
	id := r.PathValue("id")
	dest := "/devices/" + id
	kind, ok := parseKind(r.PostFormValue("kind"))
	master, ref := r.PostFormValue("master"), r.PostFormValue("ref")
	if !ok {
		h.redirectErr(w, r, dest, "detach credential", errors.New("unknown credential kind"))
		return
	}
	dev, err := h.devices.GetDevice(r.Context(), id)
	if err != nil {
		h.redirectErr(w, r, dest, "detach credential", err)
		return
	}
	// A stale page can hold a master/ref that has since moved to another device —
	// attached there directly, or freed and re-issued — so the credential named in
	// the form must still be THIS device's before anything is touched.
	if cred, ok := dev.Credential(kind, master); !ok || cred.Ref != ref {
		h.redirectErr(w, r, dest, "detach credential", errors.New("that credential does not belong to this device — reload the page"))
		return
	}
	consequence := "The profile loses this proxy on its next update. The credential stays on its master; its own personal link does not come back."
	if kind == domain.CredentialAWG && dev.Token == ref {
		consequence += " This device's link is this credential's ID, so the device gets a NEW link: hand it out again."
	}
	if h.needsConfirmation(w, r, confirmView{
		Title: "Detach credential", Heading: "Detach this credential?", Consequence: consequence,
		Action: dest + "/detach", ConfirmLabel: "Detach", CancelHref: dest, Hidden: formHidden(r),
	}) {
		return
	}
	if err := h.devices.DetachCredential(r.Context(), kind, master, ref); err != nil {
		h.redirectErr(w, r, dest, "detach credential", err)
		return
	}
	h.audit(r, "detach credential", "device", id, "kind", string(kind), "master", master)
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (h *Handler) handleDeviceRename(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	if h.devices == nil {
		http.NotFound(w, r)
		return
	}
	id, name := r.PathValue("id"), strings.TrimSpace(r.PostFormValue("name"))
	dest := "/devices/" + id
	if !validClientName(name) {
		h.redirectErr(w, r, dest, "rename device", errors.New("name must be 1-64 chars of letters, digits, '-', '_' or '.'"))
		return
	}
	if err := h.devices.RenameDevice(r.Context(), id, name); err != nil {
		h.redirectErr(w, r, dest, "rename device", deviceActionError(err, name, "", ""))
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (h *Handler) handleDeviceRotate(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	if h.devices == nil {
		http.NotFound(w, r)
		return
	}
	id := r.PathValue("id")
	dest := "/devices/" + id
	if h.needsConfirmation(w, r, confirmView{
		Title: "Rotate link", Heading: "Rotate this device's link?",
		Consequence: "The current link and subscription stop working at once. The app keeps its last profile and its tunnels keep working, but it will not update until the person re-subscribes with the new link.",
		Detail:      "Use this when a link has leaked. Credentials and keys are unchanged.",
		Action:      dest + "/rotate", ConfirmLabel: "Rotate link", CancelHref: dest,
	}) {
		return
	}
	if _, err := h.devices.RotateDeviceToken(r.Context(), id); err != nil {
		h.redirectErr(w, r, dest, "rotate link", err)
		return
	}
	h.audit(r, "rotate device link", "device", id)
	h.setFlashOK(w, "Link rotated — hand out the new one below.")
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (h *Handler) handleDeviceDelete(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	if h.devices == nil {
		http.NotFound(w, r)
		return
	}
	id := r.PathValue("id")
	dest := "/devices/" + id
	if h.needsConfirmation(w, r, confirmView{
		Title: "Delete device", Heading: "Delete this device?",
		Consequence: "Its link and subscription stop working for good. Its credentials are not revoked: they stay on their masters, unattached, and whatever the app already holds keeps connecting. Their old personal links do not come back — to hand a credential out again, attach it to a device.",
		Detail:      "To cut access, pause or revoke the credentials on their master pages as well.",
		Action:      dest + "/delete", ConfirmLabel: "Delete device", CancelHref: dest,
	}) {
		return
	}
	if err := h.devices.DeleteDevice(r.Context(), id); err != nil {
		h.redirectErr(w, r, dest, "delete device", err)
		return
	}
	h.audit(r, "delete device", "device", id)
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

func parseKind(s string) (domain.CredentialKind, bool) {
	switch k := domain.CredentialKind(s); k {
	case domain.CredentialAWG, domain.CredentialVLESS:
		return k, true
	}
	return "", false
}

func (h *Handler) isMaster(name string) bool {
	for _, m := range h.devices.Masters() {
		if m == name {
			return true
		}
	}
	return false
}

// deviceActionError says what to do instead of printing a constraint.
func deviceActionError(err error, name, master string, kind domain.CredentialKind) error {
	switch {
	case errors.Is(err, store.ErrDeviceSlotTaken):
		what := "an AmneziaWG"
		if kind == domain.CredentialVLESS {
			what = "a VLESS"
		}
		return fmt.Errorf("this device already has %s credential on %s — detach it first", what, master)
	case errors.Is(err, store.ErrCredentialAttached):
		return errors.New("that credential belongs to another device — detach it there first")
	case errors.Is(err, store.ErrNotFound):
		return errors.New("device or credential not found — reload the page")
	case isUniqueViolation(err, "client_devices.name"):
		return fmt.Errorf("a device named %q already exists", name)
	case isUniqueViolation(err, "name"):
		return fmt.Errorf("a credential named %q already exists on %s — attach it instead of issuing a new one", name, master)
	default:
		return err
	}
}

// deviceProfileSource is clientcfg.ProfileSource over the panel's own
// dependencies (clientSource already is its clientcfg.Source half). The file the
// operator downloads and the subscription the device later polls come out of
// ONE build — clientcfg.BuildDeviceProfile — so the hand-over from the file to
// the link changes nothing but where the profile comes from.
type deviceProfileSource struct{ clientSource }

func (s deviceProfileSource) ListVLESSClients(ctx context.Context, masterID string) ([]domain.VLESSClient, error) {
	return s.h.renderer.ListVLESSClients(ctx, masterID)
}

func (s deviceProfileSource) ClientMasterMeta(ctx context.Context, masterID string) (domain.ClientMasterMeta, error) {
	return s.h.devices.ClientMasterMeta(ctx, masterID)
}

// handleDeviceProfile hands the operator a device's profile as a file — the
// FIRST import. The portal lives on the mgmt overlay, which a new device cannot
// reach before it has a tunnel; the file gives it the tunnel, and the
// subscription link, reachable through it, takes over from there. Behind the
// session like every page here, so the portal's limiter does not apply.
func (h *Handler) handleDeviceProfile(w http.ResponseWriter, r *http.Request) {
	if h.devices == nil {
		http.NotFound(w, r)
		return
	}
	dev, err := h.devices.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		httpError(w, "load device", err)
		return
	}
	yml, err := clientcfg.BuildDeviceProfile(r.Context(), deviceProfileSource{clientSource{h}}, h.devices.Masters(), dev)
	switch {
	case errors.Is(err, clientcfg.ErrNoActiveCredential):
		http.Error(w, "every credential of this device is paused, or none is attached — nothing to import", http.StatusForbidden)
		return
	case errors.Is(err, clientcfg.ErrNotReady):
		http.Error(w, "no master of this device can hand out a config yet: "+err.Error(), http.StatusServiceUnavailable)
		return
	case err != nil:
		httpError(w, "build device profile", err)
		return
	}
	// The file carries the device's AWG private key.
	h.audit(r, "download device profile", "device", dev.ID)
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", clientcfg.AttachmentHeader(clientcfg.ProfileFileName(dev)))
	_, _ = w.Write([]byte(yml))
}
