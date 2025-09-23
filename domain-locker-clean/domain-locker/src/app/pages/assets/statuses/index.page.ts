import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { PrimeNgModule } from '~/app/prime-ng.module';
import DatabaseService from '~/app/services/database.service';
import { LoadingComponent } from '~/app/components/misc/loading.component';
import { getByEppCode, type SecurityCategory, securityCategories } from '~/app/constants/security-categories';
import { ErrorHandlerService } from '~/app/services/error-handler.service';

@Component({
  standalone: true,
  selector: 'app-statuses-index',
  imports: [CommonModule, RouterModule, LoadingComponent, PrimeNgModule],
  templateUrl: './statuses.page.html',
  styleUrls: ['./statuses.page.scss'],
})
export default class StatusesIndexPageComponent implements OnInit {
  statuses: { eppCode: string; description: string; domainCount: number }[] = [];
  loading: boolean = true;
  detailedStatuses: { statusCount: number, statusInfo?: SecurityCategory }[] = [];
  public securityCategories: SecurityCategory[] = securityCategories

  constructor(
    private databaseService: DatabaseService,
    private errorHandler: ErrorHandlerService,
  ) {}

  ngOnInit() {
    this.loadStatuses();
  }

  loadStatuses() {
    this.loading = true;
    this.databaseService.instance.getStatusesWithDomainCounts().subscribe({
      next: (statusesWithCounts) => {
        this.statuses = statusesWithCounts.sort((a, b) => b.domainCount - a.domainCount);
        this.detailedStatuses = this.statuses.map(status => {
          return { statusCount: status.domainCount, statusInfo: getByEppCode(status.eppCode) };
        });
        this.securityCategories = securityCategories.filter(cat => 
          this.statuses.every(status => status.eppCode !== cat.eppCode)
        );
        this.loading = false;
      },
      error: (error) => {
        this.errorHandler.handleError({
          message: 'Failed to load statuses',
          error,
          showToast: true,
          location: 'StatusesIndexPageComponent.loadStatuses'
        });
        this.loading = false;
      }
    });
  }
}
