/*
   Higher level convience functions for setting up a container
*/

package namespaces

import (
	"errors"
	"fmt"
	"github.com/crosbymichael/libcontainer"
	"github.com/crosbymichael/libcontainer/capabilities"
	"github.com/crosbymichael/libcontainer/utils"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var (
	ErrExistingNetworkNamespace = errors.New("specified both CLONE_NEWNET and an existing network namespace")
)

// Exec will spawn new namespaces with the specified Container configuration
// in the RootFs path and return the pid of the new containerized process.
//
// If an existing network namespace is specified the container
// will join that namespace.  If an existing network namespace is not specified but CLONE_NEWNET is,
// the container will be spawned with a new network namespace with no configuration.  Omiting an
// existing network namespace and the CLONE_NEWNET option in the container configuration will allow
// the container to the the host's networking options and configuration.
func Exec(container *libcontainer.Container) (int, error) {
	if container.NetNsFd > 0 && container.Namespaces.Contains(libcontainer.CLONE_NEWNET) {
		return -1, ErrExistingNetworkNamespace
	}
	// TODO: resolve symlinks
	rootfs, err := filepath.Abs(container.RootFs)
	if err != nil {
		return -1, err
	}

	master, err := os.OpenFile("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC|syscall.O_NDELAY, 0)
	if err != nil {
		return -1, err
	}

	console, err := ptsname(master)
	if err != nil {
		return -1, err
	}

	if err := unlockpt(master); err != nil {
		return -1, err
	}

	pid, err := CloneIntoNamespace(container.Namespaces, func() error {
		println("open slave")
		slave, err := os.OpenFile(console, syscall.O_RDWR|syscall.O_NOCTTY, 0)
		if err != nil {
			return err
		}
		os.Stdin = slave
		os.Stdout = slave
		os.Stderr = slave
		println("exec action")

		return execAction(container, rootfs, console)

	})
	if err != nil {
		return -1, err
	}
	go io.Copy(master, os.Stdin)
	go io.Copy(os.Stdout, master)

	return pid, nil
}

// execAction runs inside the new namespaces and initializes the standard
// setup
func execAction(container *libcontainer.Container, rootfs, console string) error {
	fmt.Println("set ctty")
	if err := setctty(); err != nil {
		return fmt.Errorf("setctty %s", err)
	}

	println("set sid")
	if _, err := setsid(); err != nil {
		return fmt.Errorf("setsid %s", err)
	}

	if err := parentDeathSignal(); err != nil {
		return fmt.Errorf("parent deth signal %s", err)
	}

	if err := SetupNewMountNamespace(rootfs, console, container.ReadonlyFs); err != nil {
		return fmt.Errorf("setup mount namespace %s", err)
	}

	// the network namespace must be joined before chrooting the process
	if container.NetNsFd > 0 {
		if err := JoinExistingNamespace(container.NetNsFd, libcontainer.CLONE_NEWNET); err != nil {
			return fmt.Errorf("join existing net namespace %s", err)
		}
	}

	if err := chroot("."); err != nil {
		return fmt.Errorf("chroot . %s", err)
	}

	if err := chdir("/"); err != nil {
		return fmt.Errorf("chdir / %s", err)
	}

	if err := sethostname(container.ID); err != nil {
		return fmt.Errorf("sethostname %s", err)
	}

	if err := capabilities.DropCapabilities(container); err != nil {
		return fmt.Errorf("drop capabilities %s", err)
	}

	if err := setupUser(container); err != nil {
		return fmt.Errorf("setup user %s", err)
	}

	if container.WorkingDir != "" {
		if err := chdir(container.WorkingDir); err != nil {
			return fmt.Errorf("chdir to %s %s", container.WorkingDir, err)
		}
	}
	if err := exec(container.Command.Args[0], container.Command.Args[0:], container.Command.Env); err != nil {
		return err
	}
	// unreachable
	return nil
}

// ExecIn will spawn a new command inside an existing container's namespaces.  The existing container's
// pid and namespace configuration is needed along with the specific capabilities that should
// be dropped once inside the namespace.
func ExecIn(container *libcontainer.Container, cmd *libcontainer.Command) (int, error) {
	if container.NsPid <= 0 {
		return -1, libcontainer.ErrInvalidPid
	}

	fds, err := getNsFds(container)
	if err != nil {
		return -1, err
	}

	if container.NetNsFd > 0 {
		fds = append(fds, container.NetNsFd)
	}

	pid, err := fork()
	if err != nil {
		for _, fd := range fds {
			syscall.Close(int(fd))
		}
		return -1, err
	}

	if pid == 0 {
		if err := execinAction(container, cmd, fds); err != nil {
			writeError("exec in %s", err)
		}
	}
	return pid, err
}

func execinAction(container *libcontainer.Container, cmd *libcontainer.Command, fds []uintptr) error {
	for _, fd := range fds {
		if fd > 0 {
			if err := JoinExistingNamespace(fd, ""); err != nil {
				for _, fd := range fds {
					syscall.Close(int(fd))
				}
				return err
			}
		}
		syscall.Close(int(fd))
	}

	if container.Namespaces.Contains(libcontainer.CLONE_NEWNS) &&
		container.Namespaces.Contains(libcontainer.CLONE_NEWPID) {
		// important:
		// we need to fork and unshare so that re can remount proc and sys within
		// the namespace so the CLONE_NEWPID namespace will take effect
		// if we don't fork we would end up unmounting proc and sys for the entire
		// namespace
		child, err := fork()
		if err != nil {
			return fmt.Errorf("fork child %s", err)
		}

		if child == 0 {
			if err := unshare(CLONE_NEWNS); err != nil {
				writeError("unshare newns %s", err)
			}
			if err := remountProc(); err != nil {
				writeError("remount proc %s", err)
			}
			if err := remountSys(); err != nil {
				writeError("remount sys %s", err)
			}
			if err := capabilities.DropCapabilities(container); err != nil {
				writeError("drop caps %s", err)
			}

			if err := exec(cmd.Args[0], cmd.Args[0:], cmd.Env); err != nil {
				writeError("exec %s", err)
			}
			// unreachable
		}
		exit, err := utils.WaitOnPid(child)
		if err != nil {
			writeError("wait on child %s", err)
		}
		os.Exit(exit)
	}
	return nil
}
