package provider

import (
	"context"
	"time"

	"github.com/gravitational/trace"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	//dockerterm "github.com/moby/term"
	//"github.com/sirupsen/logrus"
	//"golang.org/x/sync/errgroup"
	//corev1 "k8s.io/api/core/v1"
	//metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	//"github.com/gravitational/teleport"
	//apiclient "github.com/gravitational/teleport/api/client"
	//apidefaults "github.com/gravitational/teleport/api/defaults"
	_ "github.com/gravitational/teleport/api/gen/proto/go/attestation/v1"
	"github.com/gravitational/teleport/lib/client"
	//kubeclient "github.com/gravitational/teleport/lib/client/kube"
	//kubeutils "github.com/gravitational/teleport/lib/kube/utils"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/tool/tsh/common"
)

//var log = logrus.WithFields(logrus.Fields{
//teleport.ComponentKey: teleport.ComponentTSH,
//})

var (
	kubeScheme       = runtime.NewScheme()
	kubeCodecs       = serializer.NewCodecFactory(kubeScheme)
	kubeGroupVersion = schema.GroupVersion{
		Group:   "client.authentication.k8s.io",
		Version: "v1beta1",
	}
)

// dataSourceTeleportKubeType is the data source metadata type
type dataSourceTeleportKubeType struct {
	Id                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	ProxyName         types.String `tfsdk:"proxy_name"`
	ClientKey         types.String `tfsdk:"client_key"`
	ClientCertificate types.String `tfsdk:"client_certificate"`
}

// dataSourceTeleportKube is the resource
type dataSourceTeleportKube struct {
	p Provider
}

// GetSchema returns the data source schema
func (r dataSourceTeleportKubeType) GetSchema(ctx context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{Attributes: map[string]tfsdk.Attribute{
		"id": {
			Computed:      true,
			Optional:      false,
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			Required:      false,
			Type:          types.StringType,
		},
		"name": {
			Description: "Name of the Kubernetes cluster in Teleport",
			Required:    true,
			Type:        types.StringType,
		},
		"proxy_name": {
			Description: "Name of the proxy",
			Required:    true,
			Type:        types.StringType,
		},
		"client_key": {
			Computed:      true,
			Description:   "Client key",
			Optional:      true,
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			Type:          types.StringType,
		},
		"client_certificate": {
			Computed:      true,
			Description:   "Client certificate",
			Optional:      true,
			PlanModifiers: []tfsdk.AttributePlanModifier{tfsdk.UseStateForUnknown()},
			Type:          types.StringType,
		},
	}}, nil
}

// NewDataSource creates the empty data source
func (r dataSourceTeleportKubeType) NewDataSource(_ context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	return dataSourceTeleportKube{
		p: *(p.(*Provider)),
	}, nil
}

type kubeCredentialsCommand struct {
	kubeCluster     string
	teleportCluster string
}

// Read reads teleport Kube
func (r dataSourceTeleportKube) Read(ctx context.Context, req tfsdk.ReadDataSourceRequest, resp *tfsdk.ReadDataSourceResponse) {
	var data dataSourceTeleportKubeType

	diags := req.Config.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	clusterName := data.Name.Value
	proxyName := data.ProxyName.Value

	cliConf := common.CLIConf{}

	c := common.NewKubeCredentialsCommand(clusterName, proxyName)

	err := getKubernetesCluster(ctx, c, cliConf)
	if err != nil {
		resp.Diagnostics.Append(diagFromWrappedErr("Error reading Kube", trace.Wrap(err), "db"))
		return
	}

	var state types.Object

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func getKubernetesCluster(ctx context.Context, c *common.KubeCredentialsCommand, cf common.CLIConf) error {
	profile, err := cf.GetProfile()
	if err != nil {
		return err
	}

	if err := c.CheckLocalProxyRequirement(profile); err != nil {
		return err
	}

	// client.LoadKeysToKubeFromStore function is used to speed up the credentials
	// loading process since Teleport Store transverses the entire store to find the keys.
	// This operation takes a long time when the store has a lot of keys and when
	// we call the function multiple times in parallel.
	// Although client.LoadKeysToKubeFromStore function speeds up the process since
	// it removes all transversals, it still has to read 2 different files from
	// the disk and acquire a read lock on the key file:
	// - $TSH_HOME/keys/$PROXY/$USER-kube/$TELEPORT_CLUSTER/$KUBE_CLUSTER.crt
	// - $TSH_HOME/keys/$PROXY/$USER-kube/$TELEPORT_CLUSTER/$KUBE_CLUSTER.key
	//
	// In addition to these files, $TSH_HOME/$profile.yaml is also read from
	// cf.GetProfile call above.
	if keyPEM, certPEM, err := client.LoadKeysToKubeFromStore(
		profile,
		cf.HomePath,
		c.TeleportCluster,
		c.KubeCluster,
	); err != nil {
		crt, _ := tlsca.ParseCertificatePEM(certPEM)
		if crt != nil && time.Until(crt.NotAfter) > time.Minute {
			//log.Debugf("Re-using existing TLS cert for Kubernetes cluster %q", c.kubeCluster)
			return c.WriteByteResponse(cf.Stdout(), certPEM, keyPEM, crt.NotAfter)
		}
	}

	return c.IssueCert(&cf)
}
