package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Configuration holds application settings
type Config struct {
	Port            string `json:"port"`
	LogLevel        string `json:"log_level"`
	ScanTimeout     string `json:"scan_timeout"`
	JWTSecret       string `json:"jwt_secret"`
	AWSRegion       string `json:"aws_region"`
	S3BucketName    string `json:"s3_bucket_name"`
	TrivyNoProgress bool   `json:"trivy_no_progress"`
	TrivyTimeout    string `json:"trivy_timeout"`
	TrivySkipUpdate bool   `json:"trivy_skip_update"`
	TrivyIgnoreUnfixed bool `json:"trivy_ignore_unfixed"`
	TrivySeverity   string `json:"trivy_severity"`
}

// ScanRequest represents the payload for requesting a vulnerability scan
type ScanRequest struct {
	ImageName   string `json:"image_name" binding:"required"`
	ImageTag    string `json:"image_tag" binding:"required"`
	Registry    string `json:"registry" binding:"required"`
	ForceRescan bool   `json:"force_rescan"`
}

// ScanResult represents the result of a vulnerability scan
type ScanResult struct {
	ScanID        string    `json:"scan_id"`
	ImageName     string    `json:"image_name"`
	ImageTag      string    `json:"image_tag"`
	Registry      string    `json:"registry"`
	Status        string    `json:"status"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	ErrorMessage  string    `json:"error_message,omitempty"`
}

// Vulnerability represents a security vulnerability found in an image
type Vulnerability struct {
	ID          string `json:"id"`
	Package     string `json:"package"`
	Version     string `json:"version"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	FixedIn     string `json:"fixed_in,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	Link        string `json:"link,omitempty"`
}

// In-memory storage for scan results (would use a database in production)
var scanResults = make(map[string]ScanResult)

// Prometheus metrics
var (
	scanCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vulnerability_scans_total",
			Help: "Total number of vulnerability scans",
		},
		[]string{"status", "registry"},
	)
	
	vulnerabilityCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vulnerabilities_found_total",
			Help: "Total number of vulnerabilities found",
		},
		[]string{"severity"},
	)
	
	scanDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "scan_duration_seconds",
			Help:    "Duration of vulnerability scans in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"registry"},
	)
)

// Initialize logger
var logger *zap.Logger

func init() {
	// Register Prometheus metrics
	prometheus.MustRegister(scanCounter)
	prometheus.MustRegister(vulnerabilityCounter)
	prometheus.MustRegister(scanDuration)
	
	// Initialize logger
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
}

func main() {
	// Load configuration
	config := loadConfig()
	
	// Set Gin mode based on environment
	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	
	// Create router
	router := gin.New()
	
	// Add middleware
	router.Use(gin.Recovery())
	router.Use(loggerMiddleware())
	router.Use(securityHeadersMiddleware())
	
	// Define API routes
	v1 := router.Group("/v1")
	{
		// Public endpoints
		v1.GET("/scan/healthz", healthCheckHandler)
		
		// Protected endpoints
		protected := v1.Group("/scan")
		protected.Use(authMiddleware(config.JWTSecret))
		{
			protected.POST("", createScanHandler)
			protected.GET("/:id", getScanResultHandler)
			protected.GET("/list", listScansHandler)
		}
	}
	
	// Prometheus metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))
	
	// Create HTTP server
	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", config.Port),
		Handler: router,
	}
	
	// Start server in a goroutine
	go func() {
		logger.Info("Starting vulnerability scanner service", 
			zap.String("port", config.Port),
			zap.String("log_level", config.LogLevel))
			
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", zap.Error(err))
		}
	}()
	
	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	logger.Info("Shutting down server...")
	
	// Create context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", zap.Error(err))
	}
	
	logger.Info("Server exiting")
}

// loadConfig loads application configuration from environment variables
func loadConfig() *Config {
	return &Config{
		Port:            getEnv("PORT", "8080"),
		LogLevel:        getEnv("LOG_LEVEL", "info"),
		ScanTimeout:     getEnv("SCAN_TIMEOUT", "5m"),
		JWTSecret:       getEnv("JWT_SECRET", ""),
		AWSRegion:       getEnv("AWS_REGION", "us-east-1"),
		S3BucketName:    getEnv("S3_BUCKET_NAME", ""),
		TrivyNoProgress: getEnvBool("TRIVY_NO_PROGRESS", true),
		TrivyTimeout:    getEnv("TRIVY_TIMEOUT", "5m"),
		TrivySkipUpdate: getEnvBool("TRIVY_SKIP_UPDATE", false),
		TrivyIgnoreUnfixed: getEnvBool("TRIVY_IGNORE_UNFIXED", false),
		TrivySeverity:   getEnv("TRIVY_SEVERITY", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"),
	}
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvBool gets a boolean environment variable or returns a default value
func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return strings.ToLower(value) == "true"
}

// loggerMiddleware creates a middleware for logging HTTP requests
func loggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		
		// Process request
		c.Next()
		
		// Log request details
		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()
		
		logger.Info("HTTP request",
			zap.String("path", path),
			zap.String("method", method),
			zap.Int("status", statusCode),
			zap.String("ip", clientIP),
			zap.Duration("latency", latency),
		)
	}
}

// securityHeadersMiddleware adds security headers to all responses
func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		
		c.Next()
	}
}

// authMiddleware creates a middleware for JWT authentication
func authMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		
		// Check if Authorization header exists
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}
		
		// Check if it's a Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}
		
		token := parts[1]
		
		// In a real implementation, validate JWT token here
		// For now, just check if it's not empty (placeholder for actual JWT validation)
		if token == "" || jwtSecret == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		
		// TODO: Implement proper JWT validation
		// This is a placeholder for actual JWT validation logic
		
		c.Next()
	}
}

// healthCheckHandler handles health check requests
func healthCheckHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// createScanHandler handles requests to create a new vulnerability scan
func createScanHandler(c *gin.Context) {
	var req ScanRequest
	
	// Validate request body
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}
	
	// Generate a unique scan ID
	scanID := uuid.New().String()
	
	// Create scan result
	result := ScanResult{
		ScanID:    scanID,
		ImageName: req.ImageName,
		ImageTag:  req.ImageTag,
		Registry:  req.Registry,
		Status:    "pending",
		StartTime: time.Now(),
	}
	
	// Store scan result
	scanResults[scanID] = result
	
	// Start scan in a goroutine
	go performScan(scanID, req)
	
	// Return scan ID to client
	c.JSON(http.StatusAccepted, gin.H{
		"scan_id": scanID,
		"message": "Scan initiated",
	})
}

// getScanResultHandler handles requests to get a scan result by ID
func getScanResultHandler(c *gin.Context) {
	scanID := c.Param("id")
	
	// Check if scan exists
	result, exists := scanResults[scanID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}
	
	// Return scan result
	c.JSON(http.StatusOK, result)
}

// listScansHandler handles requests to list all scans
func listScansHandler(c *gin.Context) {
	// Get query parameters for pagination
	limit := 10 // Default limit
	offset := 0 // Default offset
	
	// Parse limit and offset from query parameters
	limitParam := c.Query("limit")
	offsetParam := c.Query("offset")
	
	if limitParam != "" {
		fmt.Sscanf(limitParam, "%d", &limit)
	}
	
	if offsetParam != "" {
		fmt.Sscanf(offsetParam, "%d", &offset)
	}
	
	// Convert map to slice for pagination
	var results []ScanResult
	for _, result := range scanResults {
		results = append(results, result)
	}
	
	// Apply pagination
	end := offset + limit
	if end > len(results) {
		end = len(results)
	}
	
	if offset >= len(results) {
		c.JSON(http.StatusOK, gin.H{
			"scans": []ScanResult{},
			"total": len(results),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"scans": results[offset:end],
		"total": len(results),
	})
}

// performScan executes a vulnerability scan using Trivy
func performScan(scanID string, req ScanRequest) {
	logger.Info("Starting vulnerability scan", 
		zap.String("scan_id", scanID),
		zap.String("image", fmt.Sprintf("%s/%s:%s", req.Registry, req.ImageName, req.ImageTag)))
	
	// Update scan status to "in_progress"
	result := scanResults[scanID]
	result.Status = "in_progress"
	scanResults[scanID] = result
	
	// Start timer for metrics
	startTime := time.Now()
	
	// Prepare image name
	imageName := fmt.Sprintf("%s/%s:%s", req.Registry, req.ImageName, req.ImageTag)
	
	// Prepare Trivy command
	cmd := exec.Command(
		"trivy", 
		"image",
		"--format", "json",
		"--severity", os.Getenv("TRIVY_SEVERITY"),
		imageName,
	)
	
	// Add optional flags based on configuration
	if os.Getenv("TRIVY_NO_PROGRESS") == "true" {
		cmd.Args = append(cmd.Args, "--no-progress")
	}
	
	if os.Getenv("TRIVY_SKIP_UPDATE") == "true" {
		cmd.Args = append(cmd.Args, "--skip-update")
	}
	
	if os.Getenv("TRIVY_IGNORE_UNFIXED") == "true" {
		cmd.Args = append(cmd.Args, "--ignore-unfixed")
	}
	
	// Execute Trivy command
	output, err := cmd.CombinedOutput()
	
	// Record scan duration
	duration := time.Since(startTime)
	scanDuration.WithLabelValues(req.Registry).Observe(duration.Seconds())
	
	// Update scan result
	result = scanResults[scanID]
	result.EndTime = time.Now()
	
	if err != nil {
		// Scan failed
		logger.Error("Vulnerability scan failed",
			zap.String("scan_id", scanID),
			zap.String("image", imageName),
			zap.Error(err))
			
		result.Status = "failed"
		result.ErrorMessage = fmt.Sprintf("Scan failed: %v", err)
		scanCounter.WithLabelValues("failed", req.Registry).Inc()
	} else {
		// Scan succeeded
		logger.Info("Vulnerability scan completed",
			zap.String("scan_id", scanID),
			zap.String("image", imageName),
			zap.Duration("duration", duration))
		
		result.Status = "completed"
		
		// Parse Trivy JSON output
		var trivyResults map[string]interface{}
		if err := json.Unmarshal(output, &trivyResults); err != nil {
			result.ErrorMessage = "Failed to parse scan results"
		} else {
			// Extract vulnerabilities from Trivy results
			result.Vulnerabilities = parseVulnerabilities(trivyResults)
			
			// Count vulnerabilities by severity for metrics
			for _, vuln := range result.Vulnerabilities {
				vulnerabilityCounter.WithLabelValues(vuln.Severity).Inc()
			}
		}
		
		scanCounter.WithLabelValues("completed", req.Registry).Inc()
	}
	
	// Update scan result in storage
	scanResults[scanID] = result
}

// parseVulnerabilities extracts vulnerabilities from Trivy scan results
func parseVulnerabilities(trivyResults map[string]interface{}) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Extract vulnerabilities from Trivy JSON output
	// This is a simplified implementation - actual parsing would depend on Trivy's output format
	if results, ok := trivyResults["Results"].([]interface{}); ok {
		for _, res := range results {
			if result, ok := res.(map[string]interface{}); ok {
				if vulns, ok := result["Vulnerabilities"].([]interface{}); ok {
					for _, v := range vulns {
						if vuln, ok := v.(map[string]interface{}); ok {
							vulnerability := Vulnerability{
								ID:          getStringValue(vuln, "VulnerabilityID"),
								Package:     getStringValue(vuln, "PkgName"),
								Version:     getStringValue(vuln, "InstalledVersion"),
								Severity:    getStringValue(vuln, "Severity"),
								Description: getStringValue(vuln, "Description"),
								FixedIn:     getStringValue(vuln, "FixedVersion"),
								Link:        getStringValue(vuln, "PrimaryURL"),
							}
							
							// Try to parse CVSS score
							if cvss, ok := vuln["CVSS"].(map[string]interface{}); ok {
								if score, ok := cvss["nvd"].(map[string]interface{}); ok {
									if v3score, ok := score["V3Score"].(float64); ok {
										vulnerability.CVSS = v3score
									}
								}
							}
							
							vulnerabilities = append(vulnerabilities, vulnerability)
						}
					}
				}
			}
		}
	}
	
	return vulnerabilities
}

// getStringValue safely extracts a string value from a map
func getStringValue(m map[string]interface{}, key string) string {
	if value, ok := m[key].(string); ok {
		return value
	}
	return ""
}
