# Plugin Azure VM

## Configuration

> [!NOTE]
> Requires the typical Azure credentials to be set in your environment for the client to work. This can either be set manually or using the `az` tool

| Name | Environment Variable | Required | Description |
| --- | --- |:---:| --- |
| `subscription_id` | `$CCF_PLUGINS_AZURE_CONFIG_SUBSCRIPTION_ID` | ✅ | Subscription ID for the Azure instance |

## Building the plugin

```shell
$ mkdir -p dist
$ go build -o dist/plugin main.go
```

## Data structure passed to the policy manager

The plugin does not do any manipulation of the structures provided back from `azure-go-sdk`, so anything that is passed back can be queried in rego. However, due to the linked nature of azure with IDs through the API, the plugin saturates the data that is passed back and places them in a wrapper around structures.

The golang definition can be found below: 

```golang
type AzureVMInstance struct {
	Instance          *armcompute.VirtualMachine `json:"instance"`
	NetworkInterfaces []*AzureVMNetworkInterface `json:"network_interfaces"`
}

type AzureVMNetworkInterface struct {
	Config        *armnetwork.InterfacesClientGetResponse          `json:"config"`
	PublicIPs     []*armnetwork.PublicIPAddressesClientGetResponse `json:"public_ips,omitempty"`
	SecurityGroup *armnetwork.SecurityGroupsClientGetResponse      `json:"security_group,omitempty"`
}
```

To see what data is available, the recommendation is to look at the golang documentation for the different types:

* [`armcompute.VirtualMachine`](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/arm/compute#VirtualMachine)
* [`armnetwork.InterfacesClientGetResponse`](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7#InterfacesClientGetResponse)
* [`armnetwork.PublicIPAddressesClientGetResponse`](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7#PublicIPAddressesClientGetResponse)
* [`armnetwork.SecurityGroupsClientGetResponse`](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7#SecurityGroupsClientGetResponse)

To see the data in action, have a look at the unit tests found in the [policies repo](https://github.com/compliance-framework/plugin-azure-vm-policies/tree/main/policies)


## Licence 

[AGPL v3](./LICENSE)