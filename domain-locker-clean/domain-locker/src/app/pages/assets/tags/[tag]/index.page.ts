import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router } from '@angular/router';
import { PrimeNgModule } from '~/app/prime-ng.module';
import { ConfirmationService } from 'primeng/api';
import { DbDomain } from '~/app/../types/Database';
import DatabaseService from '~/app/services/database.service';
import { MessageService } from 'primeng/api';
import { DomainCollectionComponent } from '~/app/components/domain-things/domain-collection/domain-collection.component';
import { TagEditorComponent } from '~/app/components/forms/tag-editor/tag-editor.component';
import { TagPickListComponent } from '~/app/components/forms/tag-picklist/tag-picklist.component';
import { type Tag } from '~/app/../types/common';
import { ErrorHandlerService } from '~/app/services/error-handler.service';

@Component({
  standalone: true,
  selector: 'app-tag-domains',
  imports: [CommonModule, PrimeNgModule, DomainCollectionComponent, TagEditorComponent, TagPickListComponent],
  templateUrl: './tag.page.html',
  styleUrl: '../tags.scss',
  providers: [ConfirmationService]
})
export default class TagDomainsPageComponent implements OnInit {
  tagName: string = '';
  domains: DbDomain[] = [];
  loading: boolean = true;
  editDialogOpen: boolean = false;
  addDomainsDialogOpen: boolean = false;
  tag: Tag | any = {};

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private databaseService: DatabaseService,
    private messageService: MessageService,
    private confirmationService: ConfirmationService,
    private errorHandler: ErrorHandlerService,
  ) {}

  ngOnInit() {
    this.route.params.subscribe(params => {
      this.tagName = params['tag'];
      this.loadDomains();
      this.loadTag();
    });
    this.tag.name = this.tagName;
  }

  loadTag() {
    this.loading = true;
    this.databaseService.instance.tagQueries.getTag(this.tagName).subscribe({
      next: (tag) => {
        this.tag = tag;
        if (tag.icon && !tag.icon.includes('/')) {
          this.tag.icon = `mdi/${tag.icon}`;
        }
      },
      error: (error) => {
        this.errorHandler.handleError({
          message: 'Failed to load tag details',
          error: error,
          location: 'TagDomainsPageComponent.loadTag',
          showToast: true,
        });
        this.loading = false;
      }
    });
  }

  loadDomains() {
    this.loading = true;
    this.databaseService.instance.getDomainsByTag(this.tagName).subscribe({
      next: (domains) => {
        this.domains = domains;
        this.loading = false;
      },
      error: (error) => {
        this.errorHandler.handleError({
          message: `Failed to load domains for tag '${this.tagName}'`,
          error: error,
          location: 'TagDomainsPageComponent.loadDomains',
          showToast: true,
        });
        this.loading = false;
      }
    });
  }

  showEditDialog() {
    this.editDialogOpen = true;
  }
  
  showAddDomainsDialog() {
    this.addDomainsDialogOpen = true;
  }

  deleteTag() {
    this.confirmationService.confirm({
      message: `
        Are you sure you want to delete the "${this.tag.name}" tag?<br>
        <b class="text-red-500">This action cannot be undone.</b><br>
        <p class="text-surface-400 text-sm">Note that this will not affect the domains associated with this tag,<br>
        but they will loose their association.</p>
      `,
      header: `Tag Deletion Confirmation: ${this.tag.name}`,
      acceptButtonStyleClass: 'p-button-danger p-button-sm',
      rejectButtonStyleClass: 'p-button-secondary p-button-sm',
      accept: () => {
        this.databaseService.instance.tagQueries.deleteTag(this.tag.id).subscribe({
          next: () => {
            this.messageService.add({
              severity: 'success',
              summary: 'Success',
              detail: `Tag "${this.tag.name}" deleted successfully.`
            });
            this.router.navigate(['/assets/tags']);
          },
          error: (error) => {
            this.errorHandler.handleError({
              message: `Error deleting tag '${this.tagName}'`,
              error: error,
              location: 'TagDomainsPageComponent.deleteTag',
              showToast: true,
            });
          }
        });
      }
    });
  }

  refreshDomainsAfterDialogClose() {
    this.loadDomains();
  }

  afterAddDomainsSave() {
    this.addDomainsDialogOpen = false;
  }

  afterEditSave() {
    this.editDialogOpen = false;
  }
}
