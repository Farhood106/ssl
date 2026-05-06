<?php
declare(strict_types=1);

class DnsCheckerCoreService
{
    private string $domain;
    private DnsResolverService $resolver;
    private DnsProbeService $probe;

    public function __construct(string $domain, ?DnsResolverService $resolver = null, ?DnsProbeService $probe = null)
    {
        $this->domain = rtrim(strtolower($domain), '.');
        $this->resolver = $resolver ?? new DnsResolverService();
        $this->probe = $probe ?? new DnsProbeService($this->resolver);
    }

    public function runSections(array $sections): array
    {
        $out = [];
        foreach ($sections as $section) {
            $method = 'check' . ucfirst($section) . 'Section';
            if (method_exists($this, $method)) {
                $out[$section] = $this->{$method}();
            } else {
                $out[$section] = [];
            }
        }
        return $out;
    }

    public function runZyDnsProfile(): array
    {
        return $this->runSections(['parent', 'ns', 'soa', 'mx', 'www']);
    }

    public function runYourDnsProfile(): array
    {
        return $this->runSections(['parent', 'ns', 'soa', 'mx', 'www', 'emailSecurity', 'caa', 'dnssec']);
    }

    public function checkParentSection(): array { return []; }
    public function checkNsSection(): array { return []; }
    public function checkSoaSection(): array { return []; }
    public function checkMxSection(): array { return []; }
    public function checkWwwSection(): array { return []; }
    public function checkEmailSecuritySection(): array { return []; }
    public function checkCaaSection(): array { return []; }
    public function checkDnssecSection(): array { return []; }

    private function result(string $section, string $status, string $title, string $detail): array
    {
        return compact('section', 'status', 'title', 'detail');
    }
}
