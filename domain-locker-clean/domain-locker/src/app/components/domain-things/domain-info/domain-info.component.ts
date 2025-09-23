import { Component, Input, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { PrimeNgModule } from '~/app/prime-ng.module';
import { DomainUtils } from '~/app/services/domain-utils.service';
import { DlIconComponent } from '~/app/components/misc/svg-icon.component';
import { DomainFaviconComponent } from '~/app/components/misc/favicon.component';
import { type DbDomain } from '~/app/../types/Database';
import { SecurityCategory, makeEppArrayFromLabels } from '~/app/constants/security-categories';
import { SafeDatePipe } from '~/app/utils/safe-date.pipe';

@Component({
  standalone: true,
  selector: 'app-domain-info',
  imports: [CommonModule, PrimeNgModule, DlIconComponent, DomainFaviconComponent, SafeDatePipe],
  templateUrl: './domain-info.component.html',
  styleUrls: ['./domain-info.component.scss'],
})
export class DomainInfoComponent implements OnInit {
  @Input() domain: DbDomain | null = null;

  constructor(public domainUtils: DomainUtils) {}

  ngOnInit() {
    // Fallback in case we really fuck up the types
    if (this.domain && (this.domain as any).status) {
      this.domain.statuses = this.makeStatuses((this.domain as any).status);
    }
    if (this.domain && !this.domain.expiry_date && (this.domain as any).dates) {
      this.domain.expiry_date = (this.domain as any).dates.expiry_date;
      this.domain.registration_date = (this.domain as any).dates.creation_date;
      this.domain.updated_date = (this.domain as any).dates.updated_date;
    }
  }


public filterIpAddresses(
  ipAddresses: { ip_address: string; is_ipv6: boolean }[] | { ipv4: string[]; ipv6: string[] } | undefined,
  isIpv6: boolean
): { ip_address: string; is_ipv6: boolean }[] {
  if (!ipAddresses) return [];

  // Check if ipAddresses is in the old format
  if (Array.isArray(ipAddresses)) {
    return ipAddresses.filter(ip => ip.is_ipv6 === isIpv6);
  }

  // New format case: convert to the old format for filtering
  if ('ipv4' in ipAddresses && 'ipv6' in ipAddresses) {
    const convertedAddresses = [
      ...ipAddresses.ipv4.map(ip => ({ ip_address: ip, is_ipv6: false })),
      ...ipAddresses.ipv6.map(ip => ({ ip_address: ip, is_ipv6: true })),
    ];
    return convertedAddresses.filter(ip => ip.is_ipv6 === isIpv6);
  }

  return [];
}

  public makeStatuses(statuses: string[] | SecurityCategory[]) {
    if (typeof statuses[0] === 'string') {
      return makeEppArrayFromLabels(statuses as string[]);
    }
    return statuses as SecurityCategory[];
  }
}
