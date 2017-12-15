package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"os"
	"strings"
	"time"

	"crypto/rsa"

	"golang.org/x/crypto/ssh"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/engine"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/state"

	"github.com/joyent/gocommon/client"
	"github.com/joyent/gosdc/cloudapi"
	"github.com/joyent/gosign/auth"
)

const (
	driverName = "triton"
	flagPrefix = driverName + "-"
	// SDC_ is for historical reasons
	envPrefix = "SDC_"
)

var (
	errKeyNotRsa = errors.New("SSH key must be of type RSA")
)

var (
	defaultTritonAccount     = ""
	defaultTritonKeyPath     = os.Getenv("HOME") + "/.ssh/id_rsa"
	defaultTritonKeyContents = ""
	defaultTritonKeyId       = ""
	defaultTritonUrl         = "https://us-east-1.api.joyent.com"

	// https://docs.joyent.com/public-cloud/instances/virtual-machines/images/linux/debian#debian-8
	defaultTritonImage   = "debian-8"
	defaultTritonPackage = "g3-standard-0.25-kvm"
	defaultTritonSshUser = "root"
	defaultTritonNetwork = ""
)

type Driver struct {
	*drivers.BaseDriver

	// authentication/access parameters
	TritonAccount     string
	TritonKeyPath     string
	TritonKeyContents string
	TritonKeyId       string
	TritonUrl         string

	// machine creation parameters
	TritonImage   string
	TritonPackage string
	TritonNetwork []string

	// machine state
	TritonMachineId string
}

// SetConfigFromFlags configures the driver with the object that was returned by RegisterCreateFlags
func (d *Driver) SetConfigFromFlags(opts drivers.DriverOptions) error {
	d.TritonAccount = opts.String(flagPrefix + "account")
	d.TritonKeyPath = opts.String(flagPrefix + "key-path")
	d.TritonKeyContents = opts.String(flagPrefix + "key-contents")
	d.TritonUrl = opts.String(flagPrefix + "url")

	d.TritonImage = opts.String(flagPrefix + "image")
	d.TritonPackage = opts.String(flagPrefix + "package")
	d.BaseDriver.SSHUser = opts.String(flagPrefix + "ssh-user")
	tritonNetwork := opts.String(flagPrefix + "network")

	d.SetSwarmConfigFromFlags(opts)

	if d.TritonAccount == "" {
		return fmt.Errorf("%s driver requires the --%saccount/%sACCOUNT option", driverName, flagPrefix, envPrefix)
	}
	if d.TritonKeyPath == "" || d.TritonKeyContents == "" {
		return fmt.Errorf("%s driver requires either the --%skey-path/%sKEY_PATH or the --%skey-contents/%sKEY_CONTENTS option", driverName, flagPrefix, envPrefix, flagPrefix, envPrefix)
	}
	if d.TritonKeyPath != defaultTritonKeyPath && d.TritonKeyContents != defaultTritonKeyContents {
		return fmt.Errorf("%s driver requires --%skey-path/%sKEY_PATH and the --%skey-contents/%sKEY_CONTENTS option be mutually exclusive", driverName, flagPrefix, envPrefix, flagPrefix, envPrefix)
	}
	if d.TritonUrl == "" {
		return fmt.Errorf("%s driver requires the --%surl/%sURL option", driverName, flagPrefix, envPrefix)
	}

	if d.TritonImage == "" {
		return fmt.Errorf("%s driver requires the --%simage option", driverName, flagPrefix)
	}
	if d.TritonPackage == "" {
		return fmt.Errorf("%s driver requires the --%spackage option", driverName, flagPrefix)
	}
	if tritonNetwork != "" {
		d.TritonNetwork = strings.Split(tritonNetwork, ",")
	}

	return nil
}

// GetCreateFlags returns the mcnflag.Flag slice representing the flags that can be set, their descriptions and defaults.
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: envPrefix + "URL",
			Name:   flagPrefix + "url",
			Usage:  "URL of the CloudAPI endpoint",
			Value:  defaultTritonUrl,
		},
		mcnflag.StringFlag{
			EnvVar: envPrefix + "ACCOUNT",
			Name:   flagPrefix + "account",
			Usage:  "Login name/username",
			Value:  defaultTritonAccount,
		},
		mcnflag.StringFlag{
			EnvVar: envPrefix + "KEY_PATH",
			Name:   flagPrefix + "key-path",
			Usage:  fmt.Sprintf("A path to an SSH private key file that has been added to $%sACCOUNT", envPrefix),
			Value:  defaultTritonKeyPath,
		},
		mcnflag.StringFlag{
			EnvVar: envPrefix + "KEY_CONTENTS",
			Name:   flagPrefix + "key-contents",
			Usage:  fmt.Sprintf("The contents of an SSH private key file that has been added to $%sACCOUNT", envPrefix),
			Value:  defaultTritonKeyContents,
		},

		mcnflag.StringFlag{
			Name:  flagPrefix + "image",
			Usage: `VM image to provision ("debian-8", "debian-8@20150527", "ca291f66", etc)`,
			Value: defaultTritonImage,
		},
		mcnflag.StringFlag{
			Name:  flagPrefix + "package",
			Usage: `VM instance size to create ("g3-standard-0.25-kvm", "g3-standard-0.5-kvm", etc)`,
			Value: defaultTritonPackage,
		},
		mcnflag.StringFlag{
			Name:  flagPrefix + "ssh-user",
			Usage: `The username to login via SSH ("ubuntu", "root", etc)`,
			Value: defaultTritonSshUser,
		},
		mcnflag.StringFlag{
			Name:  flagPrefix + "network",
			Usage: `The network on which the host will be created (default is "external" and default account network)`,
			Value: defaultTritonNetwork,
		},
	}
}

func (d Driver) client() (*cloudapi.Client, error) {
	keyData := []byte(d.TritonKeyContents)
	var err error

	if len(keyData) == 0 {
		keyData, err = ioutil.ReadFile(d.TritonKeyPath)
		if err != nil {
			return nil, err
		}
	}

	// attempt to compute keyId
	privKey, err := ssh.ParseRawPrivateKey(keyData)
	if err != nil {
		return nil, err
	}

	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errKeyNotRsa
	}

	pubKey, err := ssh.NewPublicKey(rsaPrivKey.Public())
	if err != nil {
		return nil, err
	}

	// we've got it!
	d.TritonKeyId = ssh.FingerprintLegacyMD5(pubKey)

	userAuth, err := auth.NewAuth(d.TritonAccount, string(keyData), "rsa-sha256")
	if err != nil {
		return nil, err
	}

	creds := &auth.Credentials{
		UserAuthentication: userAuth,
		SdcKeyId:           d.TritonKeyId,
		SdcEndpoint:        auth.Endpoint{URL: d.TritonUrl},
	}

	return cloudapi.New(client.NewClient(
		creds.SdcEndpoint.URL,
		cloudapi.DefaultAPIVersion,
		creds,
		stdlog.New(os.Stderr, "", stdlog.LstdFlags),
	)), nil
}
func (d *Driver) getMachine() (*cloudapi.Machine, error) {
	client, err := d.client()
	if err != nil {
		return nil, err
	}
	machine, err := client.GetMachine(d.TritonMachineId)
	if err != nil {
		return nil, err
	}

	log.Debugf("machine name: %s", machine.Name)

	// update d.IPAddress since we know the value (saves later work)
	d.IPAddress = machine.PrimaryIP

	return machine, nil
}

func NewDriver(hostName, storePath string) Driver {
	return Driver{
		TritonAccount: defaultTritonAccount,
		TritonKeyPath: defaultTritonKeyPath,
		TritonKeyId:   defaultTritonKeyId,
		TritonUrl:     defaultTritonUrl,

		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
			SSHUser:     defaultTritonSshUser,
		},
	}
}

// https://github.com/docker/machine/blob/v0.7.0/libmachine/drivers/drivers.go
// https://github.com/docker/machine/blob/v0.7.0/libmachine/drivers/base.go

// Create a host using the driver's config
func (d *Driver) Create() error {
	client, err := d.client()
	if err != nil {
		return err
	}

	machineOpts := cloudapi.CreateMachineOpts{
		Name: d.MachineName,

		Image:   d.TritonImage,
		Package: d.TritonPackage,
	}
	if len(d.TritonNetwork) > 0 {
		machineOpts.Networks = d.TritonNetwork
	}
	machine, err := client.CreateMachine(machineOpts)
	if err != nil {
		return err
	}

	d.TritonMachineId = machine.Id

	return nil
}

// https://github.com/joyent/node-triton/blob/aeed6d91922ea117a42eac0cef4a3df67fbfed2f/lib/common.js#L306
func uuidToShortId(s string) string {
	return strings.SplitN(s, "-", 2)[0]
}
func iso8859(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// PreCreateCheck allows for pre-create operations to make sure a driver is ready for creation
func (d *Driver) PreCreateCheck() error {
	client, err := d.client()
	if err != nil {
		return err
	}

	// TODO find a better "Ping" method
	_, err = client.CountMachines()
	if err != nil {
		return err
	}

	if _, err := client.GetImage(d.TritonImage); err != nil {
		// apparently isn't a valid ID, but might be a name like "debian-8" (so let's do a lookup)
		// https://github.com/joyent/node-triton/blob/aeed6d91922ea117a42eac0cef4a3df67fbfed2f/lib/tritonapi.js#L368
		nameVersion := strings.SplitN(d.TritonImage, "@", 2)
		name, version := nameVersion[0], ""
		if len(nameVersion) == 2 {
			version = nameVersion[1]
		}
		filter := cloudapi.NewFilter()
		filter.Add("state", "all")
		if version != "" {
			filter.Add("name", name)
			filter.Add("version", version)
		}
		images, imagesErr := client.ListImages(filter)
		if imagesErr != nil {
			return imagesErr
		}
		nameMatches, shortIdMatches := []cloudapi.Image{}, []cloudapi.Image{}
		for _, image := range images {
			if name == image.Name {
				nameMatches = append(nameMatches, image)
			}
			if name == uuidToShortId(image.Id) {
				shortIdMatches = append(shortIdMatches, image)
			}
		}
		if len(nameMatches) == 1 {
			log.Infof("resolved image %q to %q (exact name match)", d.TritonImage, nameMatches[0].Id)
			d.TritonImage = nameMatches[0].Id
		} else if len(nameMatches) > 1 {
			mostRecent := nameMatches[0]
			published, timeErr := iso8859(mostRecent.PublishedAt)
			if timeErr != nil {
				return timeErr
			}
			for _, image := range nameMatches[1:] {
				newPublished, timeErr := iso8859(image.PublishedAt)
				if timeErr != nil {
					return timeErr
				}
				if published.Before(newPublished) {
					mostRecent = image
					published = newPublished
				}
			}
			log.Infof("resolved image %q to %q (most recent of %d name matches)", d.TritonImage, mostRecent.Id, len(nameMatches))
			d.TritonImage = mostRecent.Id
		} else if len(shortIdMatches) == 1 {
			log.Infof("resolved image %q to %q (exact short id match)", d.TritonImage, shortIdMatches[0].Id)
			d.TritonImage = shortIdMatches[0].Id
		} else {
			if len(shortIdMatches) > 1 {
				log.Warnf("image %q is an ambiguous short id", d.TritonImage)
			}
			return err
		}
	}

	for networkIdx, networkId := range d.TritonNetwork {
		var networks []cloudapi.Network
		if _, err := client.GetNetwork(networkId); err != nil {
			if networks == nil {
				var networksErr error
				networks, networksErr = client.ListNetworks()
				if networksErr != nil {
					return networksErr
				}
			}

			// eww linear search
			nameMatches, shortIdMatches := []cloudapi.Network{}, []cloudapi.Network{}
			for _, net := range networks {
				if net.Name == networkId {
					nameMatches = append(nameMatches, net)
				} else if uuidToShortId(net.Id) == networkId {
					shortIdMatches = append(shortIdMatches, net)
				}
			}

			if len(nameMatches) == 1 {
				log.Infof("resolved network %q to %q (exact name match)", networkId, nameMatches[0].Id)
				d.TritonNetwork[networkIdx] = nameMatches[0].Id
			} else if len(nameMatches) > 1 {
				log.Warnf("network %q matched multiple networks", networkId)
				return err
			} else if len(shortIdMatches) == 1 {
				log.Infof("reolved network %q to %q (exact short id match)", networkId, shortIdMatches[0].Id)
				d.TritonNetwork[networkIdx] = shortIdMatches[0].Id
			} else {
				if len(shortIdMatches) > 1 {
					log.Warnf("network %q is an ambiguous short id", networkId)
				}
				return err
			}
		}
	}

	// GetPackage (and CreateMachine) both support package names and UUIDs interchangeably
	if _, err := client.GetPackage(d.TritonPackage); err != nil {
		return err
	}

	// We need to store the key temporarily if we've been given it on the command line
	// XXX: This only works on Linux :(
	if d.TritonKeyContents != defaultTritonKeyContents {
		tmpfile, err := ioutil.TempFile("", "rancher_ssh_key")
		if err != nil {
			return err
		}
		tmpfile.Chmod(0600)
		err = os.Remove(tmpfile.Name())
		if err != nil {
			log.Errorf("could not remove temporary file %q", tmpfile.Name())
			return err
		}

		_, err = tmpfile.WriteString(d.TritonKeyContents)
		if err != nil {
			return err
		}
		if err = tmpfile.Sync(); err != nil {
			return err
		}

		d.SSHKeyPath = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), tmpfile.Fd())
	}

	return nil
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return driverName
}

// GetIP returns an IP or hostname that this host is available at
// e.g. 1.2.3.4 or docker-host-d60b70a14d3a.cloudapp.net
func (d *Driver) GetIP() (string, error) {
	if d.IPAddress != "" {
		return d.IPAddress, nil
	}
	machine, err := d.getMachine()
	if err != nil {
		return "", err
	}
	return machine.PrimaryIP, nil
}

// GetSSHHostname returns hostname for use with ssh
func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

// GetURL returns a Docker compatible host URL for connecting to this host
// e.g. tcp://1.2.3.4:2376
func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("tcp://%s:%d", ip, engine.DefaultPort), nil
}

func (d *Driver) GetSSHKeyPath() string {
	return d.TritonKeyPath
}

// GetState returns the state that the host is in (running, stopped, etc)
func (d *Driver) GetState() (state.State, error) {
	// https://github.com/docker/machine/blob/v0.7.0/libmachine/state/state.go

	machine, err := d.getMachine()
	if err != nil {
		return state.Error, err
	}

	// https://github.com/joyent/smartos-live/blob/master/src/vm/man/vmadm.1m.md#vm-states
	switch machine.State {
	case "configured", "provisioning":
		return state.Starting, nil
	case "failed", "receiving":
		return state.Error, nil
	case "running":
		return state.Running, nil
	case "shutting_down", "stopping":
		return state.Stopping, nil
	case "down", "stopped":
		return state.Stopped, nil
	}

	return state.Error, fmt.Errorf("unknown Triton instance state: %s", machine.State)
}

// Kill stops a host forcefully
func (d *Driver) Kill() error {
	// TODO find something more forceful than "Stop"
	return d.Stop()
}

// Remove a host
func (d *Driver) Remove() error {
	client, err := d.client()
	if err != nil {
		return err
	}
	return client.DeleteMachine(d.TritonMachineId)
}

// Restart a host. This may just call Stop(); Start() if the provider does not have any special restart behaviour.
func (d *Driver) Restart() error {
	client, err := d.client()
	if err != nil {
		return err
	}
	return client.RebootMachine(d.TritonMachineId)
}

// Start a host
func (d *Driver) Start() error {
	client, err := d.client()
	if err != nil {
		return err
	}
	return client.StartMachine(d.TritonMachineId)
}

// Stop a host gracefully
func (d *Driver) Stop() error {
	client, err := d.client()
	if err != nil {
		return err
	}
	return client.StopMachine(d.TritonMachineId)
}
