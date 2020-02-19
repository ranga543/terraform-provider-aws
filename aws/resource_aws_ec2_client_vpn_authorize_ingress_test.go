package aws

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

func TestAccAwsEc2ClientVpnAuthorizeIngress_basic(t *testing.T) {
	var rule1 ec2.AuthorizationRule
	rStr := acctest.RandString(5)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAwsEc2ClientVpnAuthorizeIngressDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccEc2ClientVpnNetworkAssociationConfig(rStr),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAwsEc2ClientVpnAuthorizeIngressExists("aws_ec2_client_vpn_authorize_ingress.test", &rule1),
				),
			},
		},
	})
}

func TestAccAwsEc2ClientVpnAuthorizeIngress_disappears(t *testing.T) {
	var rule1 ec2.AuthorizationRule
	rStr := acctest.RandString(5)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAwsEc2ClientVpnAuthorizeIngressDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccEc2ClientVpnNetworkAssociationConfig(rStr),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAwsEc2ClientVpnAuthorizeIngressExists("aws_ec2_client_vpn_authorize_ingress.test", &rule1),
					testAccCheckAwsEc2ClientVpnAuthorizeIngressDisappears(&rule1),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccCheckAwsEc2ClientVpnAuthorizeIngressDestroy(s *terraform.State) error {
	conn := testAccProvider.Meta().(*AWSClient).ec2conn

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_ec2_client_vpn_authorize_ingress" {
			continue
		}

		clientVpnEndpointID, targetCidr, desc, groupID, err := ec2DecodeClientVpnIngressID(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("[DESTROY ERROR] Client VPN authorize ingress %s", err.Error)
		}
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

		resp, _ := conn.DescribeClientVpnAuthorizationRules(&ec2.DescribeClientVpnAuthorizationRulesInput{
			ClientVpnEndpointId: aws.String(rs.Primary.Attributes["client_vpn_endpoint_id"]),
			Filters:             filters,
		})

		if len(resp.AuthorizationRules) > 0 {
			return fmt.Errorf("[DESTROY ERROR] Client VPN authorize ingress (%s) not deleted", rs.Primary.ID)
		}
	}

	return nil
}

func getIDsFromAuthorizationRule(rule *ec2.AuthorizationRule) (string, string, string, string) {
	clientVpnEndpointID := aws.StringValue(rule.ClientVpnEndpointId)
	targetCidr := aws.StringValue(rule.DestinationCidr)
	groupID := aws.StringValue(rule.GroupId)
	desc := aws.StringValue(rule.Description)
	if groupID == nil || groupId == "" {
		groupID = "none"
	}
	if desc == nil || desc == "" {
		desc = "none"
	}
	return clientVpnEndpointDd, targetCidr, desc, groupID
}

func testAccCheckAwsEc2ClientVpnAuthorizeIngressDisappears(rule *ec2.AuthorizationRule) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := testAccProvider.Meta().(*AWSClient).ec2conn

		clientVpnEndpointID, targetNetworkCidr, description, groupID, err := getIDsFromAuthorizationRule(rule)
		_, err := conn.RevokeClientVpnIngress(&ec2.RevokeClientVpnIngressInput{
			ClientVpnEndpointId: rule.ClientVpnEndpointId,
			TargetNetworkCidr:   rule.DestinationCidr,
			AccessGroupId:       rule.GroupId,
		})

		if err != nil {
			return err
		}

		stateConf := &resource.StateChangeConf{
			Pending: []string{ec2.ClientVpnAuthorizationRuleStatusCodeRevoking},
			Target:  []string{""},
			Refresh: ec2ClientVpnAuthorizeIngressRefreshFunc(conn, TargetNetworkCidr, clientVpnEndpointID, groupID, description),
			Timeout: 10 * time.Minute,
		}

		_, err = stateConf.WaitForState()

		return err
	}
}

func testAccCheckAwsEc2ClientVpnAuthorizeIngressExists(name string, rule *ec2.AuthorizationRule) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		clientVpnEndpointID, targetCidr, desc, groupID, error := ec2DecodeClientVpnIngressID(rs.Primary.ID)
		if error != nil {
			return fmt.Errorf("Error parsing Client VPN authorize ingress ID %s", err.Error)
		}
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

		conn := testAccProvider.Meta().(*AWSClient).ec2conn

		resp, err := conn.DescribeClientVpnAuthorizationRules(&ec2.DescribeClientVpnAuthorizationRulesInput{
			ClientVpnEndpointId: aws.String(rs.Primary.Attributes["client_vpn_endpoint_id"]),
			Filters:             filters,
		})

		if err != nil {
			return fmt.Errorf("Error reading Client VPN network association (%s): %s", rs.Primary.ID, err)
		}

		if len(resp.AuthorizationRules) > 0 {
			*rule = *resp.AuthorizationRules[0]
		}

		return fmt.Errorf("Client VPN network association (%s) not found", rs.Primary.ID)
	}
}

func testAccEc2ClientVpnNetworkAssociationConfigAcmCertificateBase() string {
	key := tlsRsaPrivateKeyPem(2048)
	certificate := tlsRsaX509SelfSignedCertificatePem(key, "example.com")

	return fmt.Sprintf(`
resource "aws_acm_certificate" "test" {
  certificate_body = "%[1]s"
  private_key      = "%[2]s"
}
`, tlsPemEscapeNewlines(certificate), tlsPemEscapeNewlines(key))
}

func testAccEc2ClientVpnNetworkAssociationConfig(rName string) string {
	return testAccEc2ClientVpnNetworkAssociationConfigAcmCertificateBase() + fmt.Sprintf(`
data "aws_availability_zones" "available" {
  # InvalidParameterValue: AZ us-west-2d is not currently supported. Please choose another az in this region
  blacklisted_zone_ids = ["usw2-az4"]
  state                = "available"
}

resource "aws_vpc" "test" {
  cidr_block = "10.1.0.0/16"

  tags = {
    Name = "terraform-testacc-subnet-%s"
  }
}

resource "aws_subnet" "test" {
  availability_zone       = data.aws_availability_zones.available.names[0]
  cidr_block              = "10.1.1.0/24"
  vpc_id                  = "${aws_vpc.test.id}"
  map_public_ip_on_launch = true

  tags = {
    Name = "tf-acc-subnet-%s"
  }
}

resource "aws_ec2_client_vpn_endpoint" "test" {
  description            = "terraform-testacc-clientvpn-%s"
  server_certificate_arn = "${aws_acm_certificate.test.arn}"
  client_cidr_block      = "10.0.0.0/16"

  authentication_options {
    type                       = "certificate-authentication"
    root_certificate_chain_arn = "${aws_acm_certificate.test.arn}"
  }

  connection_log_options {
    enabled = false
  }
}

resource "aws_ec2_client_vpn_network_association" "test" {
  client_vpn_endpoint_id = "${aws_ec2_client_vpn_endpoint.test.id}"
  subnet_id              = "${aws_subnet.test.id}"
}
`, rName, rName, rName)
}
