//go:build linux

package main

// #include "ctypes.h"
import "C"
import (
	"context"
	"device-volume-driver/internal/cgroup"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	_ "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const pluginId = "dvd"
const rootPath = "/host"

func Ptr[T any](v T) *T {
	return &v
}

func main() {
	log.Println("Starting device-mapping-manager...")

	// 1. 首先扫描现有容器
	log.Println("Scanning existing containers for device mappings...")
	scanExistingContainers()

	// 2. 然后监听新的容器事件
	log.Println("Starting to listen for new container events...")
	listenForMounts()
}

func getDeviceInfo(devicePath string) (string, int64, int64, error) {
	var stat unix.Stat_t

	if err := unix.Stat(devicePath, &stat); err != nil {
		log.Println(err)
		return "", -1, -1, err
	}

	var deviceType string

	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFBLK:
		deviceType = "b"
	case unix.S_IFCHR:
		deviceType = "c"
	default:
		log.Println("aborting: device is neither a character or block device")
		return "", -1, -1, fmt.Errorf("unsupported device type... aborting")
	}

	major := int64(unix.Major(stat.Rdev))
	minor := int64(unix.Minor(stat.Rdev))

	log.Printf("Found device: %s %s %d:%d\n", devicePath, deviceType, major, minor)

	return deviceType, major, minor, nil
}

// scanExistingContainers 扫描所有现有的运行中容器并处理设备映射
func scanExistingContainers() {
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("Failed to create Docker client: %v", err)
		return
	}
	defer cli.Close()

	// 获取所有运行中的容器
	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		log.Printf("Failed to list containers: %v", err)
		return
	}

	log.Printf("Found %d existing containers, processing device mappings...", len(containers))

	for _, container := range containers {
		log.Printf("Processing existing container: %s (%s)", container.Names[0], container.ID[:12])
		processContainer(ctx, cli, container.ID)
	}

	log.Printf("Finished processing %d existing containers", len(containers))
}

// processContainer 处理单个容器的设备映射
func processContainer(ctx context.Context, cli *client.Client, containerID string) {
	info, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		log.Printf("Failed to inspect container %s: %v", containerID[:12], err)
		return
	}

	// 检查容器是否正在运行
	if info.State.Status != "running" {
		log.Printf("Container %s is not running (status: %s), skipping", containerID[:12], info.State.Status)
		return
	}

	pid := info.State.Pid
	if pid == 0 {
		log.Printf("Container %s has no PID, skipping", containerID[:12])
		return
	}

	version, err := cgroup.GetDeviceCGroupVersion("/", pid)
	if err != nil {
		log.Printf("Failed to get cgroup version for container %s (PID %d): %v", containerID[:12], pid, err)
		return
	}

	log.Printf("Container %s: cgroup version %d, PID %d", containerID[:12], version, pid)

	// 处理容器的所有挂载点
	for _, mount := range info.Mounts {
		processContainerMount(ctx, cli, containerID, mount, pid, version)
	}
}

// processContainerMount 处理容器的单个挂载点
func processContainerMount(ctx context.Context, cli *client.Client, containerID string, mount types.MountPoint, pid int, cgroupVersion int) {
	log.Printf("Container %s: checking mount %s -> %s", containerID[:12], mount.Source, mount.Destination)

	var devicePath string

	// 🎯 核心逻辑：基于容器内目标路径判断设备分配
	if strings.HasPrefix(mount.Destination, "/dev/") {
		log.Printf("Container %s: target path %s is a device path, processing...", containerID[:12], mount.Destination)

		// 直接使用宿主机对应的设备路径
		devicePath = mount.Destination

		// 特殊处理常见设备路径
		switch mount.Destination {
		case "/dev/dri":
			devicePath = "/dev/dri"
			log.Printf("Container %s: mapping to GPU devices at %s", containerID[:12], devicePath)
		case "/dev/nvidia0", "/dev/nvidiactl", "/dev/nvidia-uvm":
			devicePath = mount.Destination
			log.Printf("Container %s: mapping to NVIDIA device %s", containerID[:12], devicePath)
		default:
			log.Printf("Container %s: mapping to device %s", containerID[:12], devicePath)
		}
	} else {
		// 如果目标路径不是设备路径，尝试从源路径解析（保持原有逻辑）
		if !strings.HasPrefix(mount.Source, "/dev") {
			log.Printf("Container %s: %s is not a device, skipping", containerID[:12], mount.Source)
			return
		}

		devicePath = mount.Source
	}

	log.Printf("Container %s: processing device path: %s", containerID[:12], devicePath)

	api, err := cgroup.New(cgroupVersion)
	if err != nil {
		log.Printf("Container %s: failed to create cgroup API: %v", containerID[:12], err)
		return
	}

	cgroupPath, sysfsPath, err := api.GetDeviceCGroupMountPath("/", pid)
	if err != nil {
		log.Printf("Container %s: failed to get cgroup mount path: %v", containerID[:12], err)
		return
	}

	cgroupPath = path.Join(rootPath, sysfsPath, cgroupPath)
	log.Printf("Container %s: cgroup path is %s", containerID[:12], cgroupPath)

	// 检查设备路径是否存在
	fileInfo, err := os.Stat(devicePath)
	if err != nil {
		log.Printf("Container %s: device %s not accessible: %v", containerID[:12], devicePath, err)
		return
	}

	// 处理设备（可能是单个设备或设备目录）
	if fileInfo.IsDir() {
		log.Printf("Container %s: processing device directory %s", containerID[:12], devicePath)
		err := filepath.Walk(devicePath, func(subDevicePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			log.Printf("Container %s: applying rules for device %s", containerID[:12], subDevicePath)
			if err = applyDeviceRules(api, subDevicePath, cgroupPath, pid); err != nil {
				log.Printf("Container %s: failed to apply device rules for %s: %v", containerID[:12], subDevicePath, err)
			}

			// 创建容器内的设备节点
			if err = createDeviceNodeInContainerFromPath(containerID, pid, subDevicePath, mount.Destination); err != nil {
				log.Printf("Container %s: failed to create device node for %s: %v", containerID[:12], subDevicePath, err)
			}
			return nil
		})
		if err != nil {
			log.Printf("Container %s: failed to walk device directory %s: %v", containerID[:12], devicePath, err)
		}
	} else {
		log.Printf("Container %s: applying rules for single device %s", containerID[:12], devicePath)
		if err = applyDeviceRules(api, devicePath, cgroupPath, pid); err != nil {
			log.Printf("Container %s: failed to apply device rules for %s: %v", containerID[:12], devicePath, err)
		}

		// 创建容器内的设备节点
		if err = createDeviceNodeInContainerFromPath(containerID, pid, devicePath, mount.Destination); err != nil {
			log.Printf("Container %s: failed to create device node for %s: %v", containerID[:12], devicePath, err)
		}
	}
}

func listenForMounts() {
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()

	// 监听容器启动和重启事件
	msgs, errs := cli.Events(
		ctx,
		types.EventsOptions{
			Filters: filters.NewArgs(
				filters.Arg("event", "start"),
				filters.Arg("event", "restart"),
				filters.Arg("event", "unpause"),
			),
		},
	)

	log.Println("Listening for container events...")
	for {
		select {
		case err := <-errs:
			log.Printf("Docker events error: %v", err)
			// 不要 Fatal，而是继续监听
			continue
		case msg := <-msgs:
			log.Printf("Received container event: %s for container %s", msg.Action, msg.Actor.ID[:12])
			processContainer(ctx, cli, msg.Actor.ID)
		}
	}
}

// createDeviceNodeInContainerFromPath 根据宿主机设备路径在容器内创建对应的设备节点
func createDeviceNodeInContainerFromPath(containerID string, pid int, hostDevicePath string, containerBasePath string) error {
	// 获取设备信息
	deviceType, major, minor, err := getDeviceInfo(hostDevicePath)
	if err != nil {
		return fmt.Errorf("failed to get device info for %s: %v", hostDevicePath, err)
	}

	// 计算容器内的设备路径
	// 例如：/dev/dri/card0 -> /dev/dri/card0
	relativePath := strings.TrimPrefix(hostDevicePath, "/dev/")
	containerDevicePath := filepath.Join(containerBasePath, filepath.Base(hostDevicePath))

	// 如果是目录挂载（如 /dev/dri），保持相对路径结构
	if strings.Contains(relativePath, "/") {
		containerDevicePath = filepath.Join(containerBasePath, filepath.Base(hostDevicePath))
	}

	return createDeviceNodeInContainer(containerID, pid, hostDevicePath, containerDevicePath, deviceType, major, minor)
}

// createDeviceNodeInContainer 在容器内创建设备节点
func createDeviceNodeInContainer(containerID string, pid int, hostDevicePath string, containerDevicePath string, deviceType string, major, minor int64) error {
	log.Printf("Container %s: creating device node %s in container", containerID[:12], containerDevicePath)

	// 构建 nsenter 命令，进入容器的命名空间
	cmd := exec.Command("nsenter",
		"-t", strconv.Itoa(pid),  // 目标进程 PID
		"-m",                     // 挂载命名空间
		"-p",                     // PID 命名空间
		"mknod",                  // 创建设备节点
		containerDevicePath,      // 容器内路径
		deviceType,               // 设备类型 (c 或 b)
		strconv.FormatInt(major, 10), // 主设备号
		strconv.FormatInt(minor, 10), // 次设备号
	)

	// 执行命令
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 如果设备节点已存在，不算错误
		if strings.Contains(string(output), "File exists") {
			log.Printf("Container %s: device node %s already exists", containerID[:12], containerDevicePath)
			return nil
		}
		log.Printf("Container %s: failed to create device node %s: %v, output: %s",
			containerID[:12], containerDevicePath, err, string(output))
		return err
	}

	log.Printf("Container %s: successfully created device node %s", containerID[:12], containerDevicePath)

	// 设置设备节点权限
	chmodCmd := exec.Command("nsenter",
		"-t", strconv.Itoa(pid),
		"-m", "-p",
		"chmod", "666", containerDevicePath,  // 给予读写权限
	)

	if output, err := chmodCmd.CombinedOutput(); err != nil {
		log.Printf("Container %s: failed to set permissions for %s: %v, output: %s",
			containerID[:12], containerDevicePath, err, string(output))
		// 权限设置失败不算致命错误
	} else {
		log.Printf("Container %s: set permissions for device node %s", containerID[:12], containerDevicePath)
	}

	return nil
}

func applyDeviceRules(api cgroup.Interface, mountPath string, cgroupPath string, pid int) error {
	deviceType, major, minor, err := getDeviceInfo(mountPath)

	if err != nil {
		log.Println(err)
		return err
	} else {
		log.Printf("Adding device rule for process %d at %s\n", pid, cgroupPath)
		err = api.AddDeviceRules(cgroupPath, []cgroup.DeviceRule{
			{
				Access: "rwm",
				Major:  Ptr[int64](major),
				Minor:  Ptr[int64](minor),
				Type:   deviceType,
				Allow:  true,
			},
		})

		if err != nil {
			log.Println(err)
			return err
		}
	}

	return nil
}
