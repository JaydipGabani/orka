package patchverification

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestDockerSendFlagsPolicy(test *testing.T) {
	for _, platform := range []string{dockerPlatformAMD64, dockerPlatformARM64} {
		for _, network := range []string{Offline, LocalServices} {
			test.Run(platform+"/"+network, func(test *testing.T) {
				content, err := dockerSeccomp(platform, network)
				if err != nil {
					test.Fatal(err)
				}
				var profile dockerSeccompProfile
				if err := json.Unmarshal(content, &profile); err != nil {
					test.Fatal(err)
				}
				for name, index := range map[string]uint{"sendto": 3, "sendmsg": 2, "sendmmsg": 3} {
					matches := 0
					for _, rule := range profile.Syscalls {
						if rule.Action != dockerSeccompAllow || !slices.Contains(rule.Names, name) {
							continue
						}
						matches++
						var expected []dockerSeccompArgument
						if network == LocalServices {
							expected = []dockerSeccompArgument{{Index: index, Value: 0x20000000, Op: "SCMP_CMP_MASKED_EQ"}}
						}
						if !slices.Equal(rule.Args, expected) {
							test.Errorf("%s flags do not preserve the %s contract: %+v", name, network, rule.Args)
						}
					}
					if matches != 1 {
						test.Errorf("%s has %d allowing rules, want one", name, matches)
					}
				}
			})
		}
	}
}

func TestDockerSocketpairPolicy(test *testing.T) {
	for _, network := range []string{Offline, LocalServices} {
		content, err := dockerSeccomp(dockerPlatformAMD64, network)
		if err != nil {
			test.Fatal(err)
		}
		var profile dockerSeccompProfile
		if err := json.Unmarshal(content, &profile); err != nil {
			test.Fatal(err)
		}
		matches := 0
		for _, rule := range profile.Syscalls {
			if rule.Action != dockerSeccompAllow || !slices.Contains(rule.Names, "socketpair") {
				continue
			}
			matches++
			expected := []dockerSeccompArgument{{Index: 0, Value: 1, Op: dockerSeccompEqual}}
			if network == LocalServices {
				expected = append(expected, dockerSeccompArgument{Index: 1, Value: ^uint64(0x80000 | 0x800), ValueTwo: 1, Op: "SCMP_CMP_MASKED_EQ"})
			}
			if !slices.Equal(rule.Args, expected) {
				test.Errorf("socketpair does not preserve the %s contract: %+v", network, rule.Args)
			}
		}
		if matches != 1 {
			test.Errorf("socketpair has %d allowing rules, want one", matches)
		}
	}
}
