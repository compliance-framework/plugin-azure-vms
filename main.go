package main

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-azure-vms/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type CompliancePlugin struct {
	logger hclog.Logger
	config map[string]string
}

type AzureVMInstance struct {
	Instance *armcompute.VirtualMachine `json:"instance"`
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
		},
	})

	// create credential service for azure
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		l.logger.Error("unable to get Azure credentials", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	vmClient, err := armcompute.NewVirtualMachinesClient(l.config["subscription_id"], cred, nil)
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

		labels := map[string]string{
			"provider":    "azure",
			"type":        "virtual-machine",
			"instance-id": vm.ID(),
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
						Text: internal.StringAddressed("The Continuous Compliance Framework' Azure VM Plugin"),
					},
				},
			},
		}

		compoents := []*proto.Component{
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
				internal.MergeMaps(
					labels,
					map[string]string{
						"_policy_path": policyPath,
					},
				),
				subjects,
				compoents,
				inventory,
				actors,
				activities,
			)

			evidence, err := processor.GenerateResults(ctx, policyPath, vm)
			evidences = slices.Concat(evidences, evidence)

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
				if !yield(azureInstance, nil) {
					return
				}
			}
		}
	}

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
