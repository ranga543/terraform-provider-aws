package aws

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceAwsEc2ClientVpnAuthorizeIngress() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsEc2ClientVpnAuthorizeIngressCreate,
		Read:   resourceAwsEc2ClientVpnAuthorizeIngressRead,
		Delete: resourceAwsEc2ClientVpnAuthorizeIngressDelete,

		Schema: map[string]*schema.Schema{
			"client_vpn_endpoint_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"target_network_cidr": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"access_group_id": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"authorize_all_groups": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"client_token": {
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func resourceAwsEc2ClientVpnAuthorizeIngressCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	clientVpnEndpointID := d.Get("client_vpn_endpoint_id").(string)
	targetNetworkCidr := d.Get("target_network_cidr").(string)
	description := "none"
	groupID := "none"
	req := &ec2.AuthorizeClientVpnIngressInput{
		ClientVpnEndpointId: aws.String(clientVpnEndpointID),
		TargetNetworkCidr:   aws.String(targetNetworkCidr),
	}
	if v, ok := d.GetOk("access_group_id"); ok {
		groupID = v.(string)
		req.AccessGroupId = aws.String(groupID)
	}
	if v, ok := d.GetOk("authorize_all_groups"); ok {
		req.AuthorizeAllGroups = aws.Bool(v.(bool))
	}
	if v, ok := d.GetOk("description"); ok {
		description = v.(string)
		req.Description = aws.String(description)
	}
	if v, ok := d.GetOk("client_token"); ok {
		req.ClientToken = aws.String(v.(string))
	}

	log.Printf("[DEBUG] Creating Client VPN Authorize Ingress: %#v", req)
	_, err := conn.AuthorizeClientVpnIngress(req)
	if err != nil {
		return fmt.Errorf("Error creating Client VPN Authorize Ingress: %s", err)
	}

	d.SetId(fmt.Sprintf("%s_%s_%s_%s_%s", clientVpnEndpointID, targetNetworkCidr, description, groupID, time.Now().UTC().String()))

	stateConf := &resource.StateChangeConf{
		Pending: []string{ec2.ClientVpnAuthorizationRuleStatusCodeAuthorizing},
		Target:  []string{ec2.ClientVpnAuthorizationRuleStatusCodeActive},
		Refresh: ec2ClientVpnAuthorizeIngressRefreshFunc(conn, targetNetworkCidr, clientVpnEndpointID, groupID, description),
		Timeout: d.Timeout(schema.TimeoutCreate),
	}

	log.Printf("[DEBUG] Waiting for Client VPN endpoint to Authorize Ingress: %s", d.Id())
	_, err = stateConf.WaitForState()
	if err != nil {
		return fmt.Errorf("Error waiting for Client VPN endpoint to Authorize Ingress: %s", err)
	}

	return resourceAwsEc2ClientVpnNetworkAssociationRead(d, meta)
}

func resourceAwsEc2ClientVpnAuthorizeIngressRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn
	var err error

	clientVpnEndpointID, targetNetworkCidr, description, groupID, err := ec2DecodeClientVpnIngressID(d.Id())
	if err != nil {
		return fmt.Errorf("Error reading Client VPN Authorize Ingress id: %s", err)
	}

	result, err := ec2ClientVpnAuthorizeIngressGet(conn, targetNetworkCidr, clientVpnEndpointID, groupID, description)

	if isAWSErr(err, "InvalidClientVpnAssociationId.NotFound", "") || isAWSErr(err, "InvalidClientVpnEndpointId.NotFound", "") {
		log.Printf("[WARN] EC2 Client VPN Authorize Ingress (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	if err != nil {
		return fmt.Errorf("Error reading Client VPN Authorize Ingress: %s", err)
	}

	if result == nil {
		log.Printf("[WARN] EC2 Client VPN Authorize Ingress (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	if result.Status != nil && aws.StringValue(result.Status.Code) == ec2.ClientVpnAuthorizationRuleStatusCodeRevoking {
		log.Printf("[WARN] EC2 Client VPN Authorize Ingress (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	d.Set("client_vpn_endpoint_id", result.ClientVpnEndpointId)
	d.Set("status", result.Status.Code)
	d.Set("target_cidr", result.DestinationCidr)
	d.Set("description", result.Description)
	d.Set("group_id", result.GroupId)
	d.Set("access_all", result.AccessAll)

	return nil
}

func resourceAwsEc2ClientVpnAuthorizeIngressDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	clientVpnEndpointID, targetNetworkCidr, desc, groupID, err := ec2DecodeClientVpnIngressID(d.Id())
	if err != nil {
		return fmt.Errorf("Error reading Client VPN Authorize Ingress id: %s", err)
	}

	input := &ec2.RevokeClientVpnIngressInput{
		ClientVpnEndpointId: aws.String(clientVpnEndpointID),
		TargetNetworkCidr:   aws.String(targetNetworkCidr),
	}
	if groupID != "none" {
		input.AccessGroupId = aws.String(groupID)
	}
	if v, ok := d.GetOk("access_all"); ok {
		input.RevokeAllGroups = aws.Bool(v.(bool))
	}
	_, err = conn.RevokeClientVpnIngress(input)

	if err != nil {
		return fmt.Errorf("Error deleting Client VPN Authorize Ingress rule: %s", err)
	}

	stateConf := &resource.StateChangeConf{
		Pending: []string{ec2.ClientVpnAuthorizationRuleStatusCodeRevoking},
		Target:  []string{""},
		Refresh: ec2ClientVpnAuthorizeIngressRefreshFunc(conn, targetNetworkCidr, clientVpnEndpointID, groupID, desc),
		Timeout: d.Timeout(schema.TimeoutDelete),
	}

	log.Printf("[DEBUG] Waiting for Client VPN endpoint to revoke with authorize rule: %s", d.Id())
	_, err = stateConf.WaitForState()
	if err != nil {
		return fmt.Errorf("Error waiting for Client VPN endpoint to revoke authorize rule: %s", err)
	}

	return nil
}

func ec2ClientVpnAuthorizeIngressRefreshFunc(conn *ec2.EC2, targetCidr string, cvepID string, groupID string, desc string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		rule, err := ec2ClientVpnAuthorizeIngressGet(conn, targetCidr, cvepID, groupID, desc)
		if err != nil {
			return nil, "", err
		}
		if rule == nil {
			return 42, ec2.ClientVpnAuthorizationRuleStatusCodeFailed, nil
		}
		return rule, aws.StringValue(rule.Status.Code), nil
	}
}

func ec2ClientVpnAuthorizeIngressGet(conn *ec2.EC2, targetCidr string, cvepID string, groupID string, desc string) (*ec2.AuthorizationRule, error) {
	filters := []*ec2.Filter{
		{
			Name:   aws.String("destination-cidr"),
			Values: []*string{aws.String(targetCidr)},
		},
	}
	if groupID != "none" {
		filters = append(filters, &ec2.Filter{
			Name:   aws.String("group-id"),
			Values: []*string{aws.String(groupID)},
		})
	}
	if desc != "none" {
		filters = append(filters, &ec2.Filter{
			Name:   aws.String("description"),
			Values: []*string{aws.String(desc)},
		})
	}
	resp, err := conn.DescribeClientVpnAuthorizationRules(&ec2.DescribeClientVpnAuthorizationRulesInput{
		ClientVpnEndpointId: aws.String(cvepID),
		Filters:             filters,
	})

	if err != nil {
		return nil, err
	}

	if resp == nil || len(resp.AuthorizationRules) == 0 || resp.AuthorizationRules[0] == nil {
		return nil, nil
	}

	return resp.AuthorizationRules[0], nil
}

func ec2DecodeClientVpnIngressID(id string) (string, string, string, string, error) {
	parts := strings.Split(id, "_")

	if len(parts) != 5 {
		return "", "", "", "", fmt.Errorf("Unexpected format of ID (%q), expected cvpn-endpoint-ID_TargetCidr_Description_GroupID", id)
	}

	return parts[0], parts[1], parts[2], parts[3], nil
}
