package main

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-azure-vms/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type CompliancePlugin struct {
	logger           hclog.Logger
	config           map[string]string
	azureCredentials *azidentity.DefaultAzureCredential
}

type AzureVMInstance struct {
	Instance          *armcompute.VirtualMachine `json:"instance"`
	NetworkInterfaces []*AzureVMNetworkInterface `json:"network_interfaces"`
}

func (i *AzureVMInstance) ID() string {
	if i.Instance == nil || i.Instance.ID == nil {
		return ""
	}
	return *i.Instance.ID
}

func (i *AzureVMInstance) Name() string {
	if i.Instance == nil || i.Instance.Name == nil {
		return ""
	}
	return *i.Instance.Name
}

type AzureVMNetworkInterface struct {
	Config        *armnetwork.InterfacesClientGetResponse          `json:"config"`
	PublicIPs     []*armnetwork.PublicIPAddressesClientGetResponse `json:"public_ips,omitempty"`
	SecurityGroup *armnetwork.SecurityGroupsClientGetResponse      `json:"security_group,omitempty"`
}

type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.config = req.GetConfig()
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	l.logger.Debug("Eval called with request", "request", request)
	ctx := context.TODO()
	evalStatus := proto.ExecutionStatus_SUCCESS
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	activities = append(activities, &proto.Activity{
		Title:       "Collect Azure VM configurations",
		Description: "Collect Azure VM configurations using the Azure SDK for Go.",
		Steps: []*proto.Step{
			{
				Title:       "Initialize Azure SDK",
				Description: "Initialize the Azure SDK with the provided credentials and subscription ID.",
			},
			{
				Title:       "List Azure VMs",
				Description: "List all Azure VMs in the specified subscription.",
			},
			{
				Title:       "Get Attached Network Interfaces",
				Description: "For each VM, retrieve the attached network interfaces and their details.",
			},
			{
				Title:       "Get Public IP Addresses",
				Description: "For each network interface, retrieve the associated public IP addresses.",
			},
			{
				Title:       "Get Attached Security Groups",
				Description: "For each network interface, retrieve the associated security groups and their rules.",
			},
		},
	})

	// create credential service for azure
	creds, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		l.logger.Error("unable to get Azure credentials", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}
	l.azureCredentials = creds

	vmClient, err := armcompute.NewVirtualMachinesClient(l.config["subscription_id"], l.azureCredentials, nil)
	if err != nil {
		l.logger.Error("unable to create Azure VM client", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	for vm, err := range l.GetVMs(ctx, vmClient) {
		if err != nil {
			l.logger.Error("Error getting VM", "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			evalStatus = proto.ExecutionStatus_FAILURE
			break
		}

		idParts, err := internal.ParseAzureResourceID(vm.ID())
		if err != nil {
			l.logger.Error("unable to parse VM ID", "error", err, "vm_id", vm.ID())
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			evalStatus = proto.ExecutionStatus_FAILURE
			break
		}

		labels := map[string]string{
			"provider":        "azure",
			"type":            "virtual-machine",
			"instance-id":     vm.ID(),
			"resource-group":  idParts["resourceGroups"],
			"location":        *vm.Instance.Location,
			"subscription-id": idParts["subscriptions"],
		}

		actors := []*proto.OriginActor{
			{
				Title: "The Continuous Compliance Framework",
				Type:  "assessment-platform",
				Links: []*proto.Link{
					{
						Href: "https://compliance-framework.github.io/docs/",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework"),
					},
				},
			},
			{
				Title: "Continuous Compliance Framework - Azure VM Plugin",
				Type:  "tool",
				Links: []*proto.Link{
					{
						Href: "https://github.com/compliance-framework/plugin-azure-vms",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework's Azure VM Plugin"),
					},
				},
			},
		}

		components := []*proto.Component{
			{
				Identifier:  "common-components/azure-virtual-machine",
				Type:        "service",
				Title:       "Azure Virtual Machine",
				Description: "An Azure Virtual Machine (VM) is a scalable compute resource that runs on the Azure cloud platform.",
				Purpose:     "Virtual compute infrastructure for compute based applications",
			},
		}

		inventory := []*proto.InventoryItem{
			{
				Identifier: "azure-vm/" + vm.ID(),
				Type:       "virtual-machine",
				Title:      fmt.Sprintf("Azure VM [%s]", vm.ID()),
				Props: []*proto.Property{
					{
						Name:  "vm-id",
						Value: vm.ID(),
					},
					{
						Name:  "vm-name",
						Value: vm.Name(),
					},
				},
			},
		}

		subjects := []*proto.Subject{
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
				Identifier: "common-components/azure-virtual-machine",
			},
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
				Identifier: "azure-vm/" + vm.ID(),
			},
		}

		evidences := make([]*proto.Evidence, 0)
		for _, policyPath := range request.GetPolicyPaths() {

			processor := policyManager.NewPolicyProcessor(
				l.logger,
				labels,
				subjects,
				components,
				inventory,
				actors,
				activities,
			)

			evidence, err := processor.GenerateResults(ctx, policyPath, vm)
			evidences = append(evidences, evidence...)

			if err != nil {
				l.logger.Error("Error processing policy", "error", err, "policyPath", policyPath, "vm_id", vm.ID())
				accumulatedErrors = errors.Join(accumulatedErrors, err)
			}
		}

		if err = apiHelper.CreateEvidence(ctx, evidences); err != nil {
			l.logger.Error("Failed to send evidences", "error", err)
			evalStatus = proto.ExecutionStatus_FAILURE
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			continue
		}
	}

	// For now, we will just return a success response.
	return &proto.EvalResponse{
		Status: evalStatus,
	}, accumulatedErrors
}

func (l *CompliancePlugin) GetVMs(ctx context.Context, client *armcompute.VirtualMachinesClient) iter.Seq2[*AzureVMInstance, error] {

	return func(yield func(*AzureVMInstance, error) bool) {
		l.logger.Debug("Getting Azure Virtual Machines")

		pager := client.NewListAllPager(nil)

		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				l.logger.Error("unable to list VM instances", "error", err)
				yield(nil, err)
				return
			}

			for _, vm := range page.Value {
				azureInstance := &AzureVMInstance{
					Instance: vm,
				}
				if vm.Properties.NetworkProfile != nil {
					config, err := l.GetNetworkConfig(ctx, vm.Properties.NetworkProfile)
					if err != nil {
						l.logger.Error("unable to get network interfaces", "error", err)
						yield(nil, err)
						return
					}
					azureInstance.NetworkInterfaces = config
				}

				if !yield(azureInstance, nil) {
					return
				}
			}
		}
	}

}

func (l *CompliancePlugin) GetNetworkConfig(ctx context.Context, networkProfile *armcompute.NetworkProfile) ([]*AzureVMNetworkInterface, error) {
	l.logger.Debug("Getting network configuration for Azure VM")
	nicClient, err := armnetwork.NewInterfacesClient(l.config["subscription_id"], l.azureCredentials, nil)
	networkInterfaces := make([]*AzureVMNetworkInterface, len(networkProfile.NetworkInterfaces))

	if err != nil {
		l.logger.Error("unable to create Azure NIC client", "error", err)
		return nil, err
	}

	for i, nicRef := range networkProfile.NetworkInterfaces {
		nicInterface := &AzureVMNetworkInterface{
			PublicIPs: make([]*armnetwork.PublicIPAddressesClientGetResponse, 0),
		}

		nicParts, err := internal.ParseAzureResourceID(*nicRef.ID)
		if err != nil {
			l.logger.Error("unable to parse NIC ID", "error", err, "nic_id", *nicRef.ID)
			return nil, err
		}

		resp, err := nicClient.Get(ctx, nicParts["resourceGroups"], nicParts["networkInterfaces"], nil)
		if err != nil {
			l.logger.Error("unable to get NIC details", "error", err, "nic_id", *nicRef.ID)
			return nil, err
		}

		nicInterface.Config = &resp

		if resp.Properties.IPConfigurations != nil {
			for _, ipConfig := range resp.Properties.IPConfigurations {
				if ipConfig.Properties.PublicIPAddress != nil && ipConfig.Properties.PublicIPAddress.ID != nil {
					l.logger.Debug("Found Public IP configuration", "nic_id", *nicRef.ID, "ip_config_id", *ipConfig.ID, "public_ip_id", *ipConfig.Properties.PublicIPAddress.ID)
					ipParts, err := internal.ParseAzureResourceID(*ipConfig.Properties.PublicIPAddress.ID)
					if err != nil {
						l.logger.Error("unable to parse Public IP ID", "error", err, "public_ip_id", *ipConfig.Properties.PublicIPAddress.ID)
						return nil, err
					}

					publicIPClient, err := armnetwork.NewPublicIPAddressesClient(l.config["subscription_id"], l.azureCredentials, nil)
					if err != nil {
						l.logger.Error("unable to create Azure Public IP client", "error", err)
						return nil, err
					}

					publicIPResp, err := publicIPClient.Get(ctx, ipParts["resourceGroups"], ipParts["publicIPAddresses"], nil)
					if err != nil {
						l.logger.Error("unable to get Public IP details", "error", err, "public_ip_id", *ipConfig.Properties.PublicIPAddress.ID)
						return nil, err
					}
					l.logger.Debug("Found Public IP", "public_ip_id", *ipConfig.Properties.PublicIPAddress.ID, "ip_address", *publicIPResp.Properties.IPAddress)
					nicInterface.PublicIPs = append(nicInterface.PublicIPs, &publicIPResp)
				}
			}
		}

		if resp.Properties.NetworkSecurityGroup != nil && resp.Properties.NetworkSecurityGroup.ID != nil {
			sgParts, err := internal.ParseAzureResourceID(*resp.Properties.NetworkSecurityGroup.ID)
			if err != nil {
				l.logger.Error("unable to parse Network Security Group ID", "error", err, "nsg_id", *resp.Properties.NetworkSecurityGroup.ID)
				return nil, err
			}

			securityGroupClient, err := armnetwork.NewSecurityGroupsClient(l.config["subscription_id"], l.azureCredentials, nil)
			if err != nil {
				l.logger.Error("unable to create Azure Security Group client", "error", err)
				return nil, err
			}

			securityGroupResp, err := securityGroupClient.Get(ctx, sgParts["resourceGroups"], sgParts["networkSecurityGroups"], nil)
			if err != nil {
				l.logger.Error("unable to get Network Security Group details", "error", err, "nsg_id", *resp.Properties.NetworkSecurityGroup.ID)
				return nil, err
			}
			nicInterface.SecurityGroup = &securityGroupResp

		}

		networkInterfaces[i] = nicInterface
	}
	return networkInterfaces, nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("Initiating Azure Virtual Machine plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
