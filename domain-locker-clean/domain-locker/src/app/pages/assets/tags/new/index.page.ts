import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { PrimeNgModule } from '~/app/prime-ng.module';
import { DomainCollectionComponent } from '~/app/components/domain-things/domain-collection/domain-collection.component';
import { TagEditorComponent } from '~/app/components/forms/tag-editor/tag-editor.component';
import { Router } from '@angular/router';


@Component({
  standalone: true,
  selector: 'app-tag-edit',
  imports: [CommonModule, PrimeNgModule, DomainCollectionComponent, TagEditorComponent],
  template: `
  <h2 class="mb-4 ml-4">Add New Tag</h2>
  <div class="p-card p-4 m-4">
    <app-tag-editor [isAddNew]="true" ($afterSave)="afterSave($event)" />
  </div>`,
})
export default class TagAddNewPage {
  constructor(private router: Router) {}

  afterSave(tagName: string) {
    this.router.navigate([`/assets/tags/${tagName}/add-domains`]);
  }
}
