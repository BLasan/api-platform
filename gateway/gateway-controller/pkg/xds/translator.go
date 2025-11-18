/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package xds

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	fileaccesslog "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	dfpcluster "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	common_dfp "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
	dfpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	upstreamhttp "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"go.uber.org/zap"
	anypb "google.golang.org/protobuf/types/known/anypb"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	DynamicForwardProxyClusterName          = "dynamic-forward-proxy-cluster"
	ExternalProcessorGRPCServiceClusterName = "ext-processor-grpc-service"
	WebSubHubInternalClusterName            = "websubhub-internal-cluster"
)

// Translator converts API configurations to Envoy xDS resources
type Translator struct {
	logger          *zap.Logger
	accessLogConfig config.AccessLogsConfig
}

// NewTranslator creates a new translator
func NewTranslator(logger *zap.Logger, accessLogConfig config.AccessLogsConfig) *Translator {
	return &Translator{
		logger:          logger,
		accessLogConfig: accessLogConfig,
	}
}

// // TranslateConfigs translates all API configurations to Envoy resources
// // The correlationID parameter is optional and used for request tracing in logs
// func (t *Translator) TranslateConfigs(configs []*models.StoredAPIConfig, correlationID string) (map[resource.Type][]types.Resource, error) {
// 	// Create a logger with correlation ID if provided
// 	log := t.logger
// 	if correlationID != "" {
// 		log = t.logger.With(zap.String("correlation_id", correlationID))
// 	}

// 	resources := make(map[resource.Type][]types.Resource)

// 	var listeners []types.Resource
// 	var routes []types.Resource
// 	var clusters []types.Resource

// 	// We'll use a single listener on port 8080 with a single virtual host
// 	// All API routes are consolidated into one virtual host to avoid wildcard domain conflicts
// 	allRoutes := make([]*route.Route, 0)
// 	clusterMap := make(map[string]*cluster.Cluster)

// 	for _, cfg := range configs {
// 		// Include ALL configs (both deployed and pending) in the snapshot
// 		// This ensures existing APIs are not overridden when deploying new APIs

// 		// Create routes and clusters for this API
// 		routesList, clusterList, err := t.translateAPIConfig(cfg)
// 		if err != nil {
// 			log.Error("Failed to translate config",
// 				zap.String("id", cfg.ID),
// 				zap.String("name", cfg.GetAPIName()),
// 				zap.Error(err))
// 			continue
// 		}

// 		allRoutes = append(allRoutes, routesList...)

// 		// Add clusters (avoiding duplicates)
// 		for _, c := range clusterList {
// 			clusterMap[c.Name] = c
// 		}
// 	}

// 	// Add a catch-all route that returns 404 for unmatched requests
// 	// This should be the last route (lowest priority)
// 	allRoutes = append(allRoutes, &route.Route{
// 		Match: &route.RouteMatch{
// 			PathSpecifier: &route.RouteMatch_Prefix{
// 				Prefix: "/",
// 			},
// 		},
// 		Action: &route.Route_DirectResponse{
// 			DirectResponse: &route.DirectResponseAction{
// 				Status: 404,
// 			},
// 		},
// 	})

// 	// Create a single virtual host with all routes
// 	virtualHost := &route.VirtualHost{
// 		Name:    "all_apis",
// 		Domains: []string{"*"},
// 		Routes:  allRoutes,
// 	}

// 	// Always create the listener, even with no APIs deployed
// 	l, err := t.createListener([]*route.VirtualHost{virtualHost})

// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create listener: %w", err)
// 	}
// 	listeners = append(listeners, l)

// 	// Add all clusters
// 	for _, c := range clusterMap {
// 		clusters = append(clusters, c)
// 	}

// 	resources[resource.ListenerType] = listeners
// 	resources[resource.RouteType] = routes
// 	resources[resource.ClusterType] = clusters

// 	return resources, nil
// }

// TranslateConfigs translates all Async API configurations to Envoy resources
// The correlationID parameter is optional and used for request tracing in logs
func (t *Translator) TranslateAsyncConfigs(configs []*models.StoredAPIConfig, correlationID string) (map[resource.Type][]types.Resource, error) {
	// Create a logger with correlation ID if provided
	log := t.logger
	if correlationID != "" {
		log = t.logger.With(zap.String("correlation_id", correlationID))
	}

	resources := make(map[resource.Type][]types.Resource)

	var listeners []types.Resource
	var routes []types.Resource
	var clusters []types.Resource

	// We'll use a single listener on port 8080 with a single virtual host
	// All API routes are consolidated into one virtual host to avoid wildcard domain conflicts
	allRoutes := make([]*route.Route, 0)
	clusterMap := make(map[string]*cluster.Cluster)

	for _, cfg := range configs {
		// Include ALL configs (both deployed and pending) in the snapshot
		// This ensures existing APIs are not overridden when deploying new APIs

		// Create routes and clusters for this Async API
		routesList, clusterList, err := t.translateAsyncAPIConfig(cfg)
		if err != nil {
			log.Error("Failed to translate config",
				zap.String("id", cfg.ID),
				zap.String("name", cfg.GetAPIName()),
				zap.Error(err))
			continue
		}

		allRoutes = append(allRoutes, routesList...)

		// Add clusters (avoiding duplicates)
		for _, c := range clusterList {
			clusterMap[c.Name] = c
		}
	}

	// Add a catch-all route that returns 404 for unmatched requests
	// This should be the last route (lowest priority)
	allRoutes = append(allRoutes, &route.Route{
		Match: &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_Prefix{
				Prefix: "/",
			},
		},
		Action: &route.Route_DirectResponse{
			DirectResponse: &route.DirectResponseAction{
				Status: 404,
			},
		},
	})

	// Create a single virtual host with all routes
	virtualHost := &route.VirtualHost{
		Name:    "all_apis",
		Domains: []string{"*"},
		Routes:  allRoutes,
	}

	// Always create the listener, even with no APIs deployed
	l, err := t.createListener([]*route.VirtualHost{virtualHost})
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}
	websubDynamicFwdlistener, err := t.createDynamicFwdListenerForWebSubHub()
	if err != nil {
		return nil, fmt.Errorf("failed to create listener for websubhub communication: %w", err)
	}
	websubhubInternalListener, err := t.createListenerForWebSubHub()
	if err != nil {
		return nil, fmt.Errorf("failed to create internal websubhub listener: %w", err)
	}
	listeners = append(listeners, l, websubDynamicFwdlistener, websubhubInternalListener)
	// Add all clusters
	for _, c := range clusterMap {
		clusters = append(clusters, c)
	}
	// Add dynamic forward proxy cluster for WebSubHub
	dynamicForwardProxyCluster := t.createDynamicForwardProxyCluster()
	clusters = append(clusters, dynamicForwardProxyCluster)

	// Add external processor gRPC cluster
	extProcessorCluster := t.createExternalProcessorCluster()
	clusters = append(clusters, extProcessorCluster)

	// Add websubhub cluster
	upstreamURL := "http://host.docker.internal:9098"
	parsedURL, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	websubhubCluster := t.createCluster(WebSubHubInternalClusterName, parsedURL)
	clusters = append(clusters, websubhubCluster)

	resources[resource.ListenerType] = listeners
	resources[resource.RouteType] = routes
	resources[resource.ClusterType] = clusters

	return resources, nil
}

// translateAsyncAPIConfig translates a single API configuration
func (t *Translator) translateAsyncAPIConfig(cfg *models.StoredAPIConfig) ([]*route.Route, []*cluster.Cluster, error) {
	apiData, err := cfg.Configuration.Data.AsWebhookAPIData()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse webhook API data: %w", err)
	}

	// Parse upstream URL
	if len(apiData.Servers) == 0 {
		return nil, nil, fmt.Errorf("no upstream configured")
	}

	upstreamURL := apiData.Servers[0].Url
	parsedURL, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	// Create cluster for this upstream
	//clusterName := t.sanitizeClusterName(parsedURL.Host)
	c := t.createCluster(WebSubHubInternalClusterName, parsedURL)
	fmt.Println("Creating ROute per TOpic")

	// Create routes for each operation
	routesList := make([]*route.Route, 0)
	for _, op := range apiData.Channels {
		updatedPath := apiData.Context + "/" + apiData.Version + op.Path
		fmt.Printf("Updated Path: %s\n", updatedPath)
		// Always route accepts a POST request for WebSubHub calls
		r := t.createRoutePerTopic("POST", updatedPath, WebSubHubInternalClusterName, parsedURL.Path)
		routesList = append(routesList, r)
	}

	return routesList, []*cluster.Cluster{c}, nil
}

// // translateAPIConfig translates a single API configuration
// func (t *Translator) translateAPIConfig(cfg *models.StoredAPIConfig) ([]*route.Route, []*cluster.Cluster, error) {
// 	apiData := cfg.Configuration.Data

// 	// Parse upstream URL
// 	if len(apiData.Servers) == 0 {
// 		return nil, nil, fmt.Errorf("no upstream configured")
// 	}

// 	upstreamURL := apiData.Servers[0].Url
// 	parsedURL, err := url.Parse(upstreamURL)
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("invalid upstream URL: %w", err)
// 	}

// 	// Create cluster for this upstream
// 	clusterName := t.sanitizeClusterName(parsedURL.Host)
// 	c := t.createCluster(WebSubHubInternalClusterName, parsedURL)

// 	// Create routes for each operation
// 	routesList := make([]*route.Route, 0)
// 	for _, op := range apiData.Operations {
// 		r := t.createRoute(string(op.Method), apiData.Context+op.Path, clusterName, parsedURL.Path)
// 		routesList = append(routesList, r)
// 	}

// 	return routesList, []*cluster.Cluster{c}, nil
// }

// createListener creates an Envoy listener with access logging
func (t *Translator) createListener(virtualHosts []*route.VirtualHost) (*listener.Listener, error) {
	routeConfig := t.createRouteConfiguration(virtualHosts)

	// Create router filter with typed config
	routerConfig := &router.Router{}
	routerAny, err := anypb.New(routerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create router config: %w", err)
	}

	// Create HTTP connection manager
	manager := &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_AUTO,
		StatPrefix: "http",
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: routeConfig,
		},
		HttpFilters: []*hcm.HttpFilter{{
			Name: wellknown.Router,
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: routerAny,
			},
		}},
	}

	// Add access logs if enabled
	if t.accessLogConfig.Enabled {
		accessLogs, err := t.createAccessLogConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create access log config: %w", err)
		}
		manager.AccessLog = accessLogs
	}

	pbst, err := anypb.New(manager)
	if err != nil {
		return nil, err
	}

	return &listener.Listener{
		Name: "listener_http_8080",
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: 8080,
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				Name: wellknown.HTTPConnectionManager,
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: pbst,
				},
			}},
		}},
	}, nil
}

func (t *Translator) createListenerForWebSubHub() (*listener.Listener, error) {
	// Reverse proxy listener: exactly one route /websubhub/operations rewritten to /hub
	// This allows clients to call /websubhub/operations and internally reach /hub on upstream.
	routeConfig := &route.RouteConfiguration{
		Name: "websubhub-internal-route",
		VirtualHosts: []*route.VirtualHost{{
			Name:    "websubhub-internal",
			Domains: []string{"*"},
			Routes: []*route.Route{{
				Match: &route.RouteMatch{PathSpecifier: &route.RouteMatch_Path{Path: "/websubhub/operations"}},
				Action: &route.Route_Route{Route: &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{Cluster: WebSubHubInternalClusterName},
					Timeout:          durationpb.New(30 * time.Second),
					PrefixRewrite:    "/hub", // rewrite path
				}},
			}},
		}},
	}

	// External processor filter (reuse config from other listener)
	extProcConfig := &extprocv3.ExternalProcessor{
		GrpcService: &core.GrpcService{
			TargetSpecifier: &core.GrpcService_EnvoyGrpc_{EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: ExternalProcessorGRPCServiceClusterName}},
			Timeout:         durationpb.New(250 * time.Millisecond),
		},
		FailureModeAllow: false,
		ProcessingMode: &extprocv3.ProcessingMode{
			RequestHeaderMode:   extprocv3.ProcessingMode_SEND,
			ResponseHeaderMode:  extprocv3.ProcessingMode_SEND,
			RequestTrailerMode:  extprocv3.ProcessingMode_SEND,
			ResponseTrailerMode: extprocv3.ProcessingMode_SEND,
			RequestBodyMode:     extprocv3.ProcessingMode_BUFFERED,
			ResponseBodyMode:    extprocv3.ProcessingMode_BUFFERED,
		},
		MessageTimeout: &durationpb.Duration{Seconds: 20, Nanos: 250000000},
	}
	extProcAny, err := anypb.New(extProcConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ext_proc config: %w", err)
	}

	// Router filter
	routerCfg := &router.Router{}
	routerAny, err := anypb.New(routerCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal router config: %w", err)
	}

	// HttpConnectionManager for port 8083
	hcmCfg := &hcm.HttpConnectionManager{
		StatPrefix:     "websubhub_internal_8083",
		CodecType:      hcm.HttpConnectionManager_AUTO,
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{RouteConfig: routeConfig},
		HttpFilters: []*hcm.HttpFilter{
			{ // ext_proc
				Name:       "envoy.filters.http.ext_proc",
				ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: extProcAny},
			},
			{ // router last
				Name:       wellknown.Router,
				ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerAny},
			},
		},
	}

	// Attach access logs if enabled
	if t.accessLogConfig.Enabled {
		accessLogs, err := t.createAccessLogConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create access log config: %w", err)
		}
		hcmCfg.AccessLog = accessLogs
	}

	hcmAny, err := anypb.New(hcmCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal http connection manager: %w", err)
	}

	return &listener.Listener{
		Name: "websubhub-internal-8083",
		Address: &core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
			Protocol:      core.SocketAddress_TCP,
			Address:       "0.0.0.0",
			PortSpecifier: &core.SocketAddress_PortValue{PortValue: 8083},
		}}},
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				Name:       wellknown.HTTPConnectionManager,
				ConfigType: &listener.Filter_TypedConfig{TypedConfig: hcmAny},
			}},
		}},
	}, nil
}

// createDynamicFwdListenerForWebSubHub creates an Envoy listener with access logging
func (t *Translator) createDynamicFwdListenerForWebSubHub() (*listener.Listener, error) {
	// Build the route configuration for dynamic forward proxy listener
	// We ignore the passed virtualHosts here and construct the required one matching the sample.
	dynamicForwardProxyRouteConfig := &route.RouteConfiguration{
		Name: "dynamic-forward-proxy-routing",
		VirtualHosts: []*route.VirtualHost{{
			Name:    "all-domains",
			Domains: []string{"*"}, // this should be websubhub domains
			Routes: []*route.Route{{
				Match: &route.RouteMatch{PathSpecifier: &route.RouteMatch_Prefix{Prefix: "/"}},
				Action: &route.Route_Route{Route: &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{Cluster: DynamicForwardProxyClusterName},
					Timeout:          durationpb.New(30 * time.Second),
					RetryPolicy: &route.RetryPolicy{
						RetryOn:    "5xx,reset,connect-failure,refused-stream",
						NumRetries: wrapperspb.UInt32(1),
					},
				}},
			}},
		}},
	}

	// External Processor filter config
	extProcConfig := &extprocv3.ExternalProcessor{
		GrpcService: &core.GrpcService{
			TargetSpecifier: &core.GrpcService_EnvoyGrpc_{EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: ExternalProcessorGRPCServiceClusterName}},
			Timeout:         durationpb.New(250 * time.Millisecond), // 0.250s
		},
		FailureModeAllow: false,
		ProcessingMode: &extprocv3.ProcessingMode{
			RequestHeaderMode:   extprocv3.ProcessingMode_SEND,
			ResponseHeaderMode:  extprocv3.ProcessingMode_SEND,
			RequestTrailerMode:  extprocv3.ProcessingMode_SEND,
			ResponseTrailerMode: extprocv3.ProcessingMode_SEND,
			RequestBodyMode:     extprocv3.ProcessingMode_BUFFERED,
			ResponseBodyMode:    extprocv3.ProcessingMode_BUFFERED,
		},
		MessageTimeout: &durationpb.Duration{Seconds: 20, Nanos: 250000000}, // 20.25s
	}
	extProcAny, err := anypb.New(extProcConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ext_proc config: %w", err)
	}
	dnsCacheConfig := &common_dfp.DnsCacheConfig{
		// Required: unique name for the shared DNS cache
		Name: "dynamic_forward_proxy_cache",

		// Optional: how often DNS entries are refreshed
		DnsRefreshRate: durationpb.New(60 * time.Second),

		// Optional: how long hosts stay cached
		HostTtl: durationpb.New(300 * time.Second),

		// Optional: which DNS families to use (AUTO, V4_ONLY, V6_ONLY)
		DnsLookupFamily: cluster.Cluster_V4_ONLY,

		// Optional: configure Envoy’s DNS resolution behavior
		// DnsResolutionConfig: &corev3.DnsResolutionConfig{
		// 	Resolvers: []*corev3.Address{
		// 		{
		// 			Address: &corev3.Address_SocketAddress{
		// 				SocketAddress: &corev3.SocketAddress{
		// 					Address: "8.8.8.8",
		// 					PortSpecifier: &corev3.SocketAddress_PortValue{
		// 						PortValue: 53,
		// 					},
		// 				},
		// 			},
		// 		},
		// 	},
		// 	DnsResolverOptions: &corev3.DnsResolverOptions{
		// 		UseTcpForDnsLookups: true, // Use TCP for reliability
		// 	},
		// },

		// Optional: maximum number of cached hosts
		MaxHosts: &wrapperspb.UInt32Value{Value: 1024},
	}

	dfpFilterConfig := &dfpv3.FilterConfig{
		ImplementationSpecifier: &dfpv3.FilterConfig_DnsCacheConfig{
			DnsCacheConfig: dnsCacheConfig,
		},
	}

	// Dynamic forward proxy filter config placeholder (typed config fields omitted for compatibility with current go-control-plane version)
	dynamicFwdAny, err := anypb.New(dfpFilterConfig)

	// Router filter
	routerConfig := &router.Router{}
	routerAny, err := anypb.New(routerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal router config: %w", err)
	}

	httpConnManager := &hcm.HttpConnectionManager{
		StatPrefix:     "websubhub_http_8082",
		CodecType:      hcm.HttpConnectionManager_AUTO,
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{RouteConfig: dynamicForwardProxyRouteConfig},
		HttpFilters: []*hcm.HttpFilter{
			{ // ext_proc filter
				Name:       "envoy.filters.http.ext_proc",
				ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: extProcAny},
			},
			{ // dynamic forward proxy filter
				Name:       "envoy.filters.http.dynamic_forward_proxy",
				ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: dynamicFwdAny},
			},
			{ // router filter must be last
				Name:       wellknown.Router,
				ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerAny},
			},
		},
	}

	// Attach access logs if enabled
	if t.accessLogConfig.Enabled {
		accessLogs, err := t.createAccessLogConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create access log config: %w", err)
		}
		httpConnManager.AccessLog = accessLogs
	}

	hcmAny, err := anypb.New(httpConnManager)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal http connection manager: %w", err)
	}

	return &listener.Listener{
		Name: "dynamic-forward-proxy-8082",
		Address: &core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
			Protocol:      core.SocketAddress_TCP,
			Address:       "0.0.0.0",
			PortSpecifier: &core.SocketAddress_PortValue{PortValue: 8082},
		}}},
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				Name:       wellknown.HTTPConnectionManager,
				ConfigType: &listener.Filter_TypedConfig{TypedConfig: hcmAny},
			}},
		}},
	}, nil
}

// createRouteConfiguration creates a route configuration
func (t *Translator) createRouteConfiguration(virtualHosts []*route.VirtualHost) *route.RouteConfiguration {
	return &route.RouteConfiguration{
		Name:         "local_route",
		VirtualHosts: virtualHosts,
	}
}

// createRoute creates a route for an operation
func (t *Translator) createRoute(method, path, clusterName, upstreamPath string) *route.Route {
	// Check if path contains parameters (e.g., {country_code})
	hasParams := strings.Contains(path, "{")

	var pathSpecifier *route.RouteMatch_SafeRegex
	if hasParams {
		// Use regex matching for parameterized paths
		regexPattern := t.pathToRegex(path)
		pathSpecifier = &route.RouteMatch_SafeRegex{
			SafeRegex: &matcher.RegexMatcher{
				Regex: regexPattern,
			},
		}
	}

	r := &route.Route{
		Match: &route.RouteMatch{
			Headers: []*route.HeaderMatcher{{
				Name: ":method",
				HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{
					StringMatch: &matcher.StringMatcher{
						MatchPattern: &matcher.StringMatcher_Exact{
							Exact: method,
						},
					},
				},
			}},
		},
		Action: &route.Route_Route{
			Route: &route.RouteAction{
				ClusterSpecifier: &route.RouteAction_Cluster{
					Cluster: clusterName,
				},
			},
		},
	}

	// Set path specifier based on whether we have parameters
	if hasParams {
		r.Match.PathSpecifier = pathSpecifier
	} else {
		// Use exact path matching for non-parameterized paths
		r.Match.PathSpecifier = &route.RouteMatch_Path{
			Path: path,
		}
	}

	// Add path rewriting if upstream has a path prefix
	// The upstream path should be prepended to the full request path
	// For example: request /weather/US/Seattle with upstream /api/v2
	// should result in /api/v2/weather/US/Seattle
	if upstreamPath != "" && upstreamPath != "/" {
		// Use RegexRewrite to prepend the upstream path to the full request path
		r.GetRoute().RegexRewrite = &matcher.RegexMatchAndSubstitute{
			Pattern: &matcher.RegexMatcher{
				Regex: "^(.*)$",
			},
			Substitution: upstreamPath + "\\1",
		}
	}

	return r
}

// createRoutePerTopic creates a route for an operation
func (t *Translator) createRoutePerTopic(method, path, clusterName, upstreamPath string) *route.Route {
	r := &route.Route{
		Match: &route.RouteMatch{
			Headers: []*route.HeaderMatcher{{
				Name: ":method",
				HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{
					StringMatch: &matcher.StringMatcher{
						MatchPattern: &matcher.StringMatcher_Exact{
							Exact: method,
						},
					},
				},
			}},
			// QueryParameters: []*route.QueryParameterMatcher{{
			// 	Name: "topic",
			// 	QueryParameterMatchSpecifier: &route.QueryParameterMatcher_StringMatch{
			// 		StringMatch: &matcher.StringMatcher{
			// 			MatchPattern: &matcher.StringMatcher_SafeRegex{
			// 				SafeRegex: &matcher.RegexMatcher{
			// 					Regex: ".+",
			// 				},
			// 			},
			// 		},
			// 	},
			// }},
		},
		Action: &route.Route_Route{
			Route: &route.RouteAction{
				ClusterSpecifier: &route.RouteAction_Cluster{
					Cluster: clusterName,
				},
			},
		},
	}

	r.Match.PathSpecifier = &route.RouteMatch_Path{
		Path: path,
	}

	r.GetRoute().PrefixRewrite = "/hub"

	// // WebSubHub path rewriting:
	// // For cluster_host_docker_internal_9098: rewrite only the path to /hub and preserve original query params.
	// // For other clusters: rewrite to /hub with injected hub.mode=publish & hub.topic=<last segment>.
	// if clusterName == "cluster_host_docker_internal_9098" {
	// 	// Use PrefixRewrite so Envoy keeps existing query parameters untouched.
	// 	r.GetRoute().PrefixRewrite = "/hub"
	// } else {
	// 	r.GetRoute().RegexRewrite = &matcher.RegexMatchAndSubstitute{
	// 		Pattern: &matcher.RegexMatcher{
	// 			Regex: "^.*/([^/]+)$", // Capture last path segment
	// 		},
	// 		Substitution: "/hub?hub.mode=publish&hub.topic=\\1",
	// 	}
	// }

	return r
}

// createCluster creates an Envoy cluster
func (t *Translator) createCluster(name string, upstreamURL *url.URL) *cluster.Cluster {
	port := uint32(80)
	if upstreamURL.Scheme == "https" {
		port = 443
	}
	if upstreamURL.Port() != "" {
		fmt.Sscanf(upstreamURL.Port(), "%d", &port)
	}

	return &cluster.Cluster{
		Name:                 name,
		ConnectTimeout:       durationpb.New(5 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*endpoint.LocalityLbEndpoints{{
				LbEndpoints: []*endpoint.LbEndpoint{{
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{
						Endpoint: &endpoint.Endpoint{
							Address: &core.Address{
								Address: &core.Address_SocketAddress{
									SocketAddress: &core.SocketAddress{
										Protocol: core.SocketAddress_TCP,
										Address:  upstreamURL.Hostname(),
										PortSpecifier: &core.SocketAddress_PortValue{
											PortValue: port,
										},
									},
								},
							},
						},
					},
				}},
			}},
		},
	}
}

// createDynamicForwardProxyCluster creates a dynamic forward proxy cluster for WebSubHub
func (t *Translator) createDynamicForwardProxyCluster() *cluster.Cluster {
	// Note: Due to go-control-plane API limitations, we use a placeholder Any for the typed config
	// The actual DNS cache config should match the filter config in createListenerForWebSubHub
	clusterConfig := &dfpcluster.ClusterConfig{
		// optional: control connection pooling / subclusters here
	}
	clusterTypeAny, _ := anypb.New(clusterConfig)
	// clusterTypeAny := &anypb.Any{
	// 	//TypeUrl: "type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig",
	// }

	// dfpClusterConfig := &dfpCluster.ClusterConfig{
	// 	DnsCacheConfig: &dfp.DnsCacheConfig{
	// 		Name:              "dynamic_forward_proxy_cache_config",
	// 		DnsLookupFamily:   dfp.DnsLookupFamily_V4_ONLY,
	// 		MaxHosts:          1024,
	// 		DnsRefreshRate:    durationpb.New(60 * time.Second),
	// 		DnsMinRefreshRate: durationpb.New(5 * time.Second),
	// 	},
	// }

	// dfpClusterAny, _ := anypb.New(dfpClusterConfig)
	// dynamicForwardProxyCluster := &cluster.Cluster{
	// 	Name:           "dynamic_forward_proxy_cluster",
	// 	LbPolicy:       cluster.Cluster_CLUSTER_PROVIDED,
	// 	ConnectTimeout: durationpb.New(5 * time.Second),
	// 	ClusterType: &cluster.ClusterType{
	// 		Name:        "envoy.clusters.dynamic_forward_proxy",
	// 		TypedConfig: dfpClusterAny,
	// 	},
	// 	UpstreamConnectionOptions: &cluster.UpstreamConnectionOptions{
	// 		TcpKeepalive: &core.TcpKeepalive{
	// 			KeepaliveTime: &core.UInt32Value{Value: 300},
	// 		},
	// 	},
	// }

	return &cluster.Cluster{
		Name:           DynamicForwardProxyClusterName,
		ConnectTimeout: durationpb.New(5 * time.Second),
		LbPolicy:       cluster.Cluster_CLUSTER_PROVIDED,
		ClusterDiscoveryType: &cluster.Cluster_ClusterType{
			ClusterType: &cluster.Cluster_CustomClusterType{
				Name:        "envoy.clusters.dynamic_forward_proxy",
				TypedConfig: clusterTypeAny,
			},
		},
		UpstreamConnectionOptions: &cluster.UpstreamConnectionOptions{
			TcpKeepalive: &core.TcpKeepalive{
				KeepaliveTime: &wrapperspb.UInt32Value{Value: 300},
			},
		},
	}
}

// createExternalProcessorCluster creates the external processor gRPC cluster
func (t *Translator) createExternalProcessorCluster() *cluster.Cluster {
	// Create HTTP/2 protocol options for gRPC
	httpProtocolOptions := &upstreamhttp.HttpProtocolOptions{
		UpstreamProtocolOptions: &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig_{
			ExplicitHttpConfig: &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig{
				ProtocolConfig: &upstreamhttp.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
					Http2ProtocolOptions: &core.Http2ProtocolOptions{},
				},
			},
		},
	}

	http2OptionsAny, err := anypb.New(httpProtocolOptions)
	if err != nil {
		// Log error but return cluster anyway (graceful degradation)
		return &cluster.Cluster{
			Name:                 ExternalProcessorGRPCServiceClusterName,
			ConnectTimeout:       durationpb.New(5 * time.Second),
			ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
			LbPolicy:             cluster.Cluster_ROUND_ROBIN,
			LoadAssignment: &endpoint.ClusterLoadAssignment{
				ClusterName: ExternalProcessorGRPCServiceClusterName,
				Endpoints: []*endpoint.LocalityLbEndpoints{{
					LbEndpoints: []*endpoint.LbEndpoint{{
						HostIdentifier: &endpoint.LbEndpoint_Endpoint{
							Endpoint: &endpoint.Endpoint{
								Address: &core.Address{
									Address: &core.Address_SocketAddress{
										SocketAddress: &core.SocketAddress{
											Protocol: core.SocketAddress_TCP,
											Address:  "host.docker.internal",
											PortSpecifier: &core.SocketAddress_PortValue{
												PortValue: 9001,
											},
										},
									},
								},
							},
						},
					}},
				}},
			},
		}
	}

	return &cluster.Cluster{
		Name:                 ExternalProcessorGRPCServiceClusterName,
		ConnectTimeout:       durationpb.New(5 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": http2OptionsAny,
		},
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: ExternalProcessorGRPCServiceClusterName,
			Endpoints: []*endpoint.LocalityLbEndpoints{{
				LbEndpoints: []*endpoint.LbEndpoint{{
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{
						Endpoint: &endpoint.Endpoint{
							Address: &core.Address{
								Address: &core.Address_SocketAddress{
									SocketAddress: &core.SocketAddress{
										Protocol: core.SocketAddress_TCP,
										Address:  "host.docker.internal",
										PortSpecifier: &core.SocketAddress_PortValue{
											PortValue: 9001,
										},
									},
								},
							},
						},
					},
				}},
			}},
		},
	}
}

// pathToRegex converts a path with parameters to a regex pattern
// Converts paths like /{country_code}/{city} to ^/[^/]+/[^/]+$
func (t *Translator) pathToRegex(path string) string {
	// Escape special regex characters in the path, except for {}
	regex := path

	// Replace {param} with a pattern that matches any non-slash characters
	// This handles parameters like {country_code}, {city}, etc.
	for strings.Contains(regex, "{") {
		start := strings.Index(regex, "{")
		end := strings.Index(regex, "}")
		if end > start {
			// Replace {paramName} with [^/]+ (matches one or more non-slash chars)
			regex = regex[:start] + "[^/]+" + regex[end+1:]
		} else {
			break
		}
	}

	// Anchor the regex to match the entire path
	return "^" + regex + "$"
}

// sanitizeClusterName creates a valid cluster name from a hostname
func (t *Translator) sanitizeClusterName(hostname string) string {
	name := strings.ReplaceAll(hostname, ".", "_")
	name = strings.ReplaceAll(name, ":", "_")
	return "cluster_" + name
}

// sanitizeName creates a valid name from an API name
func (t *Translator) sanitizeName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "-", "_")
	return name
}

// createAccessLogConfig creates access log configuration based on format (JSON or text) to stdout
func (t *Translator) createAccessLogConfig() ([]*accesslog.AccessLog, error) {
	var fileAccessLog *fileaccesslog.FileAccessLog

	if t.accessLogConfig.Format == "json" {
		// Use JSON log format fields from config
		jsonFormat := t.accessLogConfig.JSONFields
		if len(jsonFormat) == 0 {
			return nil, fmt.Errorf("json_fields not configured in access log config")
		}

		// Convert to structpb.Struct
		jsonStruct, err := structpb.NewStruct(convertToInterface(jsonFormat))
		if err != nil {
			return nil, fmt.Errorf("failed to create json struct: %w", err)
		}

		fileAccessLog = &fileaccesslog.FileAccessLog{
			Path: "/dev/stdout",
			AccessLogFormat: &fileaccesslog.FileAccessLog_LogFormat{
				LogFormat: &core.SubstitutionFormatString{
					Format: &core.SubstitutionFormatString_JsonFormat{
						JsonFormat: jsonStruct,
					},
				},
			},
		}
	} else {
		// Use text format from config
		textFormat := t.accessLogConfig.TextFormat
		if textFormat == "" {
			return nil, fmt.Errorf("text_format not configured in access log config")
		}

		fileAccessLog = &fileaccesslog.FileAccessLog{
			Path: "/dev/stdout",
			AccessLogFormat: &fileaccesslog.FileAccessLog_LogFormat{
				LogFormat: &core.SubstitutionFormatString{
					Format: &core.SubstitutionFormatString_TextFormatSource{
						TextFormatSource: &core.DataSource{
							Specifier: &core.DataSource_InlineString{
								InlineString: textFormat,
							},
						},
					},
				},
			},
		}
	}

	// Marshal to Any
	accessLogAny, err := anypb.New(fileAccessLog)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal access log config: %w", err)
	}

	return []*accesslog.AccessLog{{
		Name: "envoy.access_loggers.file",
		ConfigType: &accesslog.AccessLog_TypedConfig{
			TypedConfig: accessLogAny,
		},
	}}, nil
}

// convertToInterface converts map[string]string to map[string]interface{} for structpb
func convertToInterface(m map[string]string) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		result[k] = v
	}
	return result
}
