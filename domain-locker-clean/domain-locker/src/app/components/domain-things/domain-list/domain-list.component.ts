import { Component, Input } from '@angular/core';
import { DbDomain } from '~/app/../types/Database';
import { PrimeNgModule } from '~/app/prime-ng.module';
import { NgFor, NgSwitch, NgSwitchCase, DatePipe, CommonModule } from '@angular/common';
import { DomainFaviconComponent } from '~/app/components/misc/favicon.component';
import { DomainUtils } from '~/app/services/domain-utils.service';
import { TranslateModule } from '@ngx-translate/core';
import { TableModule } from 'primeng/table';

@Component({
  standalone: true,
  selector: 'app-domain-list',
  templateUrl: 'domain-list.component.html',
  styleUrl: 'domain-list.component.scss',
  imports: [PrimeNgModule, NgFor, NgSwitch, NgSwitchCase, DatePipe, CommonModule, DomainFaviconComponent, TranslateModule, TableModule]
})
export class DomainListComponent {
  @Input() domains: DbDomain[] = [];
  @Input() loading: boolean = false;
  @Input() visibleColumns: any[] = [];

  constructor(public domainUtils: DomainUtils) {}
}
