package aws

import (
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceAwsEc2ClientVpnApplySecurityGroups() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsEc2ClientVpnAuthorizeIngressCreate,
		Read:   schema.Noop,
		Delete: schema.Noop,

		Schema: map[string]*schema.Schema{
			"client_vpn_endpoint_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"vpc_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"security_group_ids": {
				Type:     schema.TypeSet,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				MaxItems: 5,
			},
		},
	}
}

func resourceAwsEc2ClientVpnAuthorizeIngressCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	clientVpnEndpointID := d.Get("client_vpn_endpoint_id").(string)
	vpcID := d.Get("vpc_id").(string)
	req := &ec2.ApplySecurityGroupsToClientVpnTargetNetworkInput{
		ClientVpnEndpointId: aws.String(clientVpnEndpointID),
		VpcId:               aws.String(vpcID),
		SecurityGroupIds:    expandStringList(d.Get("security_group_ids").(*schema.Set).List()),
	}

	log.Printf("[DEBUG] Creating Client VPN Apply Security Groups: %#v", req)
	_, err := conn.ApplySecurityGroupsToClientVpnTargetNetwork(req)
	if err != nil {
		return fmt.Errorf("Error creating Client VPN Apply Security Groups: %s", err)
	}

	d.SetId(fmt.Sprintf("%s_%s", clientVpnEndpointID, vpcID))

	d.Set("client_vpn_endpoint_id", clientVpnEndpointID)
	d.Set("vpc_id", vpcID)
	d.Set("security_group_ids", d.Get("security_group_ids"))
	return nil
}

func resourceAwsEc2ClientVpnEndpointUpdate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	d.Partial(true)

	clientVpnEndpointID, vpcID, err := ec2DecodeClientVpnApplySgsID(d.Id())

	req := &ec2.ApplySecurityGroupsToClientVpnTargetNetworkInput{
		ClientVpnEndpointId: aws.String(clientVpnEndpointID),
		VpcId:               aws.String(vpcID),
	}

	if d.HasChange("security_group_ids") {
		sgIDs := expandStringList(d.Get("security_group_ids").(*schema.Set).List())
		req.SecurityGroupIds = sgIDs
	}

	if _, err := conn.ApplySecurityGroupsToClientVpnTargetNetwork(req); err != nil {
		return fmt.Errorf("Error modifying Client VPN security groups: %s", err)
	}

	d.Partial(false)
	d.Set("client_vpn_endpoint_id", clientVpnEndpointID)
	d.Set("vpc_id", vpcID)
	d.Set("security_group_ids", d.Get("security_group_ids"))
	return nil
}

func ec2DecodeClientVpnApplySgsID(id string) (string, string, error) {
	parts := strings.Split(id, "_")

	if len(parts) != 2 {
		return "", "", fmt.Errorf("Unexpected format of ID (%q), expected cvpn-endpoint-ID_vpcID", id)
	}

	return parts[0], parts[1], nil
}
