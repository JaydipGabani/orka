//go:build !linux

package journal

func (d *disk) close() error {
	return ErrUnsupported
}

func openDisk(string, bool) (*disk, error) {
	return nil, ErrUnsupported
}

func (d *disk) entries() ([]entry, error) {
	return nil, ErrUnsupported
}

func (d *disk) read(string, int) ([]byte, error) {
	return nil, ErrUnsupported
}

func (d *disk) publish(string, []byte) error {
	return ErrUnsupported
}

func (d *disk) discardPending([]string) error {
	return ErrUnsupported
}
