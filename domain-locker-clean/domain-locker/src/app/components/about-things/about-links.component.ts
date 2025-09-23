import { Component } from '@angular/core';
import { PrimeNgModule } from '~/app/prime-ng.module';
import { CommonModule } from '@angular/common';
import { aboutPages } from '~/app/pages/about/data/about-page-list';
import { DlIconComponent } from '~/app/components/misc/svg-icon.component';


@Component({
  standalone: true,
  selector: 'about-links',
  template: `
  <div class="p-card p-4 relative">
  <ul class="p-0 m-0 list-none">
    <li *ngFor="let section of sections" class="">
      <a [routerLink]="'/about/' + makeId(section.title)" class="flex flex-wrap gap-2 items-center no-underline text-default">
      <dl-icon *ngIf="section.svgIcon"
        [icon]="section.svgIcon"
        class="flex w-[1.25rem]"
        classNames="w-full h-full"
        color="var(--primary-color)"
      />
      <span class="text-lg font-semibold text-primary hover:underline">
        {{section.title}}
      </span>
      <span class="opacity-70 italic cursor-default">
        {{section.description}}
      </span>
    </a>
    </li>
  </ul>
</div>
`,
  imports: [CommonModule, PrimeNgModule, DlIconComponent],
})
export class AboutLinks {
  sections = aboutPages;
  
  makeId(title: string): string {
    return title.toLowerCase().replace(/ /g, '-');
  }
}
